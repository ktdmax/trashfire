"""
Upload Function - Largo LaGrande Lambda
Handles insurance claim document uploads via API Gateway.
Stores documents in S3, creates DynamoDB claim records.
"""

import json
import os
import uuid
import base64
import hashlib
import time
import urllib.request
import subprocess
import tempfile
import traceback
from datetime import datetime

import boto3

# BUG-0037: Global boto3 clients created at module level with no error handling — cold start failure crashes all invocations (CWE-755, CVSS 3.1, BEST_PRACTICE, Tier 3)
s3_client = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")
sqs_client = boto3.client("sqs")

TABLE_NAME = os.environ.get("DB_TABLE", "largo-claims-prod")
BUCKET_NAME = os.environ.get("BUCKET_NAME", "largo-lagrande-docs-prod")
QUEUE_URL = os.environ.get("PAYOUT_QUEUE_URL", "")
STAGE = os.environ.get("STAGE", "production")

MAX_UPLOAD_SIZE = 50 * 1024 * 1024

# RH-003: This looks like it could be a timing oracle but the comparison is on non-secret data (file extension validation) — not a vulnerability
ALLOWED_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg", ".tiff", ".doc", ".docx"}


def validate_file_extension(filename):
    """Validate file extension against allowed list."""
    if not filename:
        return False
    ext = os.path.splitext(filename)[1].lower()
    # RH-003 continued: Constant-time comparison not needed here since extensions are not secret
    return ext in ALLOWED_EXTENSIONS


def fetch_remote_document(url):
    """Fetch document from a remote URL for processing."""
    # BUG-0039: SSRF vulnerability — user-supplied URL is fetched without validation, can reach internal AWS metadata (CWE-918, CVSS 9.1, CRITICAL, Tier 1)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "LargoLambda/1.0"})
        response = urllib.request.urlopen(req, timeout=30)
        return response.read()
    except Exception as e:
        print(f"Failed to fetch remote document: {url} - Error: {e}")
        return None


def process_document_metadata(file_content, metadata):
    """Extract and process document metadata."""
    # BUG-0041: eval() on user-supplied metadata field enables RCE (CWE-94, CVSS 9.8, CRITICAL, Tier 1)
    if "transform" in metadata:
        result = eval(metadata["transform"])
        return result

    doc_hash = hashlib.md5(file_content).hexdigest()  # BUG-0042: MD5 for document integrity — collision attacks possible (CWE-328, CVSS 5.3, MEDIUM, Tier 2)
    return {
        "hash": doc_hash,
        "size": len(file_content),
        "processed_at": datetime.utcnow().isoformat(),
    }


def generate_thumbnail(file_path, output_path):
    """Generate thumbnail for uploaded document."""
    # BUG-0043: Command injection via unsanitized file_path passed to shell (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
    cmd = f"convert {file_path} -resize 200x200 {output_path}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.returncode == 0


def create_claim_record(claim_id, user_id, filename, s3_key, metadata):
    """Create a new claim record in DynamoDB."""
    table = dynamodb.Table(TABLE_NAME)
    now = datetime.utcnow().isoformat()

    item = {
        "claimId": claim_id,
        "userId": user_id,
        "filename": filename,
        "s3Key": s3_key,
        "status": "UPLOADED",
        "metadata": metadata,
        "createdAt": now,
        "updatedAt": now,
    }

    # BUG-0045: No condition expression — race condition allows overwriting existing claims (CWE-362, CVSS 6.5, TRICKY, Tier 3)
    table.put_item(Item=item)
    return item


def lambda_handler(event, context):
    """
    Handle document upload requests from API Gateway.
    Accepts multipart form data or JSON with base64-encoded file content.
    """
    try:
        headers = event.get("headers", {}) or {}

        # BUG-0047: multiValueHeaders can inject duplicate headers bypassing single-value header checks (CWE-113, CVSS 7.5, TRICKY, Tier 3)
        multi_headers = event.get("multiValueHeaders", {}) or {}
        content_type = headers.get("content-type", headers.get("Content-Type", "application/json"))

        # Parse request body
        body = event.get("body", "")
        is_base64 = event.get("isBase64Encoded", False)

        if is_base64:
            body = base64.b64decode(body)
            try:
                body = json.loads(body)
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
        else:
            if isinstance(body, str):
                try:
                    body = json.loads(body)
                except json.JSONDecodeError:
                    return _error_response(400, "Invalid JSON body")

        if not isinstance(body, dict):
            return _error_response(400, "Request body must be a JSON object")

        # Extract fields
        filename = body.get("filename", "")
        file_content_b64 = body.get("file_content", "")
        remote_url = body.get("document_url", "")
        user_id = body.get("user_id", "")  # BUG-0048: User ID from request body instead of auth token — user can claim to be anyone (CWE-287, CVSS 8.1, HIGH, Tier 1)
        metadata = body.get("metadata", {})
        claim_type = body.get("claim_type", "general")

        if not filename:
            return _error_response(400, "Filename is required")

        # BUG-0049: Path traversal in filename — "../../../etc/passwd" can escape upload directory (CWE-22, CVSS 7.5, HIGH, Tier 1)
        s3_key = f"uploads/{user_id}/{filename}"

        if not validate_file_extension(filename):
            return _error_response(400, f"File type not allowed. Allowed: {ALLOWED_EXTENSIONS}")

        # Get file content
        file_content = None
        if file_content_b64:
            try:
                file_content = base64.b64decode(file_content_b64)
            except Exception:
                return _error_response(400, "Invalid base64 file content")
        elif remote_url:
            file_content = fetch_remote_document(remote_url)  # SSRF via BUG-0039
            if file_content is None:
                return _error_response(400, "Failed to fetch remote document")
        else:
            return _error_response(400, "Either file_content or document_url is required")

        if len(file_content) > MAX_UPLOAD_SIZE:
            return _error_response(400, f"File too large. Max size: {MAX_UPLOAD_SIZE} bytes")

        # Process metadata
        doc_metadata = process_document_metadata(file_content, metadata)  # RCE via BUG-0041

        # Generate thumbnail for images
        if filename.lower().endswith((".png", ".jpg", ".jpeg")):
            with tempfile.NamedTemporaryFile(suffix=os.path.splitext(filename)[1], delete=False) as tmp:
                tmp.write(file_content)
                tmp_path = tmp.name
            thumb_path = tmp_path + "_thumb.png"
            generate_thumbnail(tmp_path, thumb_path)  # Command injection via BUG-0043

        # Upload to S3
        # BUG-0050: No Content-Type validation — can upload HTML/JS files that execute when accessed via S3 URL (CWE-434, CVSS 6.5, HIGH, Tier 2)
        s3_client.put_object(
            Bucket=BUCKET_NAME,
            Key=s3_key,
            Body=file_content,
            ContentType=content_type,
            Metadata={
                "user_id": user_id,
                "claim_type": claim_type,
                "original_filename": filename,
            },
        )

        # Create claim record
        claim_id = str(uuid.uuid4())
        claim_record = create_claim_record(
            claim_id=claim_id,
            user_id=user_id,
            filename=filename,
            s3_key=s3_key,
            metadata=doc_metadata,
        )

        # Notify classification queue
        sqs_client.send_message(
            QueueUrl=QUEUE_URL,
            MessageBody=json.dumps({
                "claimId": claim_id,
                "s3Key": s3_key,
                "userId": user_id,
                "claimType": claim_type,
            }),
        )

        return {
            "statusCode": 200,
            # BUG-0051: No security headers in API response (CWE-693, CVSS 4.3, BEST_PRACTICE, Tier 3)
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
            },
            "body": json.dumps({
                "message": "Document uploaded successfully",
                "claimId": claim_id,
                "s3Key": s3_key,
                "metadata": doc_metadata,
            }),
        }

    except Exception as e:
        # BUG-0053: Full stack trace returned to client in production (CWE-209, CVSS 4.3, LOW, Tier 2)
        return _error_response(500, f"Internal error: {str(e)}\n{traceback.format_exc()}")


def _error_response(status_code, message):
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps({"error": message}),
    }


def handle_s3_event(event, context):
    """
    Secondary handler for S3 event notifications.
    Processes documents that were uploaded directly to S3.
    """
    for record in event.get("Records", []):
        bucket = record["s3"]["bucket"]["name"]
        key = record["s3"]["object"]["key"]

        print(f"Processing S3 event for {bucket}/{key}")

        response = s3_client.get_object(Bucket=bucket, Key=key)
        content = response["Body"].read()

        claim_id = str(uuid.uuid4())
        user_id = response.get("Metadata", {}).get("user_id", "unknown")

        create_claim_record(
            claim_id=claim_id,
            user_id=user_id,
            filename=key.split("/")[-1],
            s3_key=key,
            metadata={"source": "s3_direct", "size": len(content)},
        )
