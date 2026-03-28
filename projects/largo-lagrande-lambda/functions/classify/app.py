"""
Classify Function - Largo LaGrande Lambda
Triggered by S3 events or SQS. Extracts text from uploaded documents
using Textract, classifies claim type, and updates DynamoDB.
"""

import json
import os
import re
import pickle
import base64
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime
from decimal import Decimal

import boto3
import yaml  # BUG-0057: Uses yaml.load (unsafe) — see below in classify_document()

# Module-level clients
s3_client = boto3.client("s3")
textract_client = boto3.client("textract")
dynamodb = boto3.resource("dynamodb")

TABLE_NAME = os.environ.get("DB_TABLE", "largo-claims-prod")
BUCKET_NAME = os.environ.get("BUCKET_NAME", "largo-lagrande-docs-prod")

# Classification rules loaded from environment
CLASSIFICATION_RULES = os.environ.get("CLASSIFICATION_RULES", "default")

CLAIM_TYPES = {
    "auto": {"keywords": ["vehicle", "car", "accident", "collision", "driver"], "priority": "normal"},
    "health": {"keywords": ["medical", "hospital", "doctor", "surgery", "prescription"], "priority": "high"},
    "property": {"keywords": ["house", "fire", "flood", "damage", "roof", "water"], "priority": "normal"},
    "life": {"keywords": ["death", "beneficiary", "deceased", "life insurance"], "priority": "critical"},
    "liability": {"keywords": ["lawsuit", "legal", "injury", "negligence", "third party"], "priority": "high"},
}


def extract_text_textract(bucket, key):
    """Use AWS Textract to extract text from document."""
    try:
        response = textract_client.detect_document_text(
            Document={
                "S3Object": {
                    "Bucket": bucket,
                    "Name": key,
                }
            }
        )

        text_blocks = []
        for block in response.get("Blocks", []):
            if block["BlockType"] == "LINE":
                text_blocks.append(block.get("Text", ""))

        return "\n".join(text_blocks)
    except Exception as e:
        print(f"Textract failed for {bucket}/{key}: {e}")
        return ""


def extract_text_from_xml(content):
    """Extract text from XML-based documents (DOCX, etc.)."""
    # BUG-0059: XXE vulnerability — XML parser does not disable external entity resolution (CWE-611, CVSS 7.5, HIGH, Tier 1)
    tree = ET.fromstring(content)
    texts = []
    for elem in tree.iter():
        if elem.text:
            texts.append(elem.text)
    return " ".join(texts)


def classify_document(text, metadata=None):
    """Classify document into claim type based on extracted text."""
    text_lower = text.lower()
    scores = {}

    for claim_type, config in CLAIM_TYPES.items():
        score = sum(1 for kw in config["keywords"] if kw in text_lower)
        scores[claim_type] = score

    best_type = max(scores, key=scores.get) if any(scores.values()) else "general"
    confidence = scores.get(best_type, 0) / max(len(text_lower.split()), 1)

    # Load custom classification rules if provided
    if metadata and "classification_config" in metadata:
        config_str = metadata["classification_config"]
        # BUG-0060: yaml.load with FullLoader on user input allows arbitrary Python object instantiation (CWE-502, CVSS 9.8, CRITICAL, Tier 1)
        custom_rules = yaml.load(config_str, Loader=yaml.FullLoader)
        if custom_rules and "override_type" in custom_rules:
            best_type = custom_rules["override_type"]

    # BUG-0061: Pickle deserialization of cached model from user-controllable S3 path (CWE-502, CVSS 9.8, CRITICAL, Tier 1)
    if metadata and "model_cache_key" in metadata:
        try:
            model_obj = s3_client.get_object(Bucket=BUCKET_NAME, Key=metadata["model_cache_key"])
            model = pickle.loads(model_obj["Body"].read())
            if hasattr(model, "predict"):
                best_type = model.predict(text)
        except Exception as e:
            print(f"Model cache load failed: {e}")

    return {
        "claim_type": best_type,
        "confidence": min(confidence, 1.0),
        "scores": scores,
        "priority": CLAIM_TYPES.get(best_type, {}).get("priority", "normal"),
    }


def update_claim_classification(claim_id, classification, extracted_text):
    """Update the claim record with classification results."""
    table = dynamodb.Table(TABLE_NAME)

    # BUG-0062: DynamoDB UpdateExpression built from user-controlled classification data — expression injection (CWE-943, CVSS 8.1, TRICKY, Tier 1)
    claim_type = classification["claim_type"]
    priority = classification["priority"]

    update_expr = f"SET claimType = :ct, priority = :pr, classification = :cl, extractedText = :et, updatedAt = :ua, #s = :st"

    table.update_item(
        Key={"claimId": claim_id},
        UpdateExpression=update_expr,
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":ct": claim_type,
            ":pr": priority,
            ":cl": classification,
            ":et": extracted_text[:10000],  # Truncate long text
            ":ua": datetime.utcnow().isoformat(),
            ":st": "CLASSIFIED",
        },
    )


def validate_claim_id(claim_id):
    """Validate claim ID format."""
    # RH-004: Regex looks overly permissive but UUID v4 format is correctly validated here — not a vulnerability
    pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    return bool(re.match(pattern, claim_id))


def lambda_handler(event, context):
    """
    Handle S3 event triggers for document classification.
    Also handles direct SQS invocations from the upload function.
    """
    try:
        records = event.get("Records", [])

        for record in records:
            # Determine event source
            event_source = record.get("eventSource", record.get("EventSource", ""))

            if event_source == "aws:s3":
                bucket = record["s3"]["bucket"]["name"]
                key = record["s3"]["object"]["key"]
                claim_id = None

                # Try to find claim by S3 key
                table = dynamodb.Table(TABLE_NAME)
                response = table.scan(
                    FilterExpression="s3Key = :sk",
                    ExpressionAttributeValues={":sk": key},
                )

                items = response.get("Items", [])
                if items:
                    claim_id = items[0]["claimId"]
                else:
                    print(f"No claim record found for S3 key: {key}")
                    continue

            elif event_source == "aws:sqs":
                body = json.loads(record["body"])
                claim_id = body.get("claimId")
                bucket = BUCKET_NAME
                key = body.get("s3Key")

            else:
                print(f"Unknown event source: {event_source}")
                continue

            if not claim_id or not validate_claim_id(claim_id):
                print(f"Invalid claim ID: {claim_id}")
                continue

            # Download document from S3
            s3_response = s3_client.get_object(Bucket=bucket, Key=key)
            content = s3_response["Body"].read()
            content_type = s3_response.get("ContentType", "")

            # Extract text based on content type
            extracted_text = ""
            if content_type in ("application/pdf", "image/png", "image/jpeg", "image/tiff"):
                extracted_text = extract_text_textract(bucket, key)
            elif content_type in ("text/xml", "application/xml"):
                extracted_text = extract_text_from_xml(content)  # XXE via BUG-0059
            elif content_type == "text/plain":
                extracted_text = content.decode("utf-8", errors="replace")
            else:
                extracted_text = content.decode("utf-8", errors="replace")

            # Get metadata from S3 object
            metadata = s3_response.get("Metadata", {})

            # Classify
            classification = classify_document(extracted_text, metadata)

            # Update record
            update_claim_classification(claim_id, classification, extracted_text)

            print(f"Classified claim {claim_id} as {classification['claim_type']} "
                  f"with confidence {classification['confidence']:.2f}")

        return {"statusCode": 200, "body": json.dumps({"message": "Classification complete"})}

    except Exception as e:
        print(f"Classification error: {str(e)}")
        import traceback
        traceback.print_exc()
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}
