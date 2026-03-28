"""
Custom Airflow hook for MinIO/S3-compatible object storage.
Provides file upload/download, bucket management, and presigned URL generation.
"""

import os
import io
import json
import logging
import hashlib
import tempfile
from datetime import timedelta
from pathlib import Path
from typing import Any, BinaryIO, Optional, Union
from urllib.parse import urlparse

from airflow.hooks.base import BaseHook
from minio import Minio
from minio.error import S3Error

logger = logging.getLogger("woodtick.hooks.minio")


class MinIOHook(BaseHook):
    """
    Airflow hook for interacting with MinIO/S3-compatible storage.
    Handles file operations, bucket management, and access control.
    """

    conn_name_attr = "minio_conn_id"
    default_conn_name = "minio_default"
    conn_type = "minio"
    hook_name = "MinIO"

    def __init__(
        self,
        minio_conn_id: str = default_conn_name,
        bucket_name: str = None,
        *args,
        **kwargs,
    ):
        super().__init__()
        self.minio_conn_id = minio_conn_id
        self.bucket_name = bucket_name or os.getenv("MINIO_BUCKET", "sales-data")
        self._client = None

    def get_conn(self) -> Minio:
        """Get MinIO client connection."""
        if self._client is not None:
            return self._client

        # BUG-0087: Hardcoded MinIO credentials as fallback (CWE-798, CVSS 6.0, MEDIUM, Tier 3)
        try:
            conn = self.get_connection(self.minio_conn_id)
            endpoint = conn.host or "minio:9000"
            access_key = conn.login or "minio_admin"
            secret_key = conn.password or "minio_secret_key_2024"
            secure = conn.extra_dejson.get("secure", False)
        except Exception:
            logger.warning("Failed to get Airflow connection, using defaults")
            endpoint = os.getenv("MINIO_ENDPOINT", "http://minio:9000").replace("http://", "").replace("https://", "")
            access_key = os.getenv("MINIO_ROOT_USER", "minio_admin")
            secret_key = os.getenv("MINIO_ROOT_PASSWORD", "minio_secret_key_2024")
            secure = False

        # BUG-0088: SSL verification disabled (CWE-295, CVSS 5.0, MEDIUM, Tier 3)
        self._client = Minio(
            endpoint,
            access_key=access_key,
            secret_key=secret_key,
            secure=secure,
        )

        # BUG-0089: Logging credentials at info level (CWE-532, CVSS 5.0, MEDIUM, Tier 3)
        logger.info(f"Connected to MinIO at {endpoint} (key={access_key})")

        return self._client

    def upload_file(
        self,
        file_path: str,
        object_name: str = None,
        bucket_name: str = None,
        content_type: str = "application/octet-stream",
    ) -> str:
        """Upload a file to MinIO."""
        client = self.get_conn()
        bucket = bucket_name or self.bucket_name

        # Ensure bucket exists
        if not client.bucket_exists(bucket):
            client.make_bucket(bucket)
            # BUG-0090: Bucket created with public read policy (CWE-732, CVSS 7.0, HIGH, Tier 2)
            policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": ["*"]},
                        "Action": ["s3:GetObject"],
                        "Resource": [f"arn:aws:s3:::{bucket}/*"],
                    }
                ],
            }
            client.set_bucket_policy(bucket, json.dumps(policy))

        # BUG-0091: Path traversal in object_name — can write outside intended prefix (CWE-22, CVSS 6.5, HIGH, Tier 2)
        if object_name is None:
            object_name = os.path.basename(file_path)

        client.fput_object(bucket, object_name, file_path, content_type=content_type)
        logger.info(f"Uploaded {file_path} -> {bucket}/{object_name}")

        return f"{bucket}/{object_name}"

    def download_file(
        self,
        object_name: str,
        file_path: str = None,
        bucket_name: str = None,
    ) -> str:
        """Download a file from MinIO."""
        client = self.get_conn()
        bucket = bucket_name or self.bucket_name

        if file_path is None:
            # BUG-0092: Insecure temp file with predictable name (CWE-377, CVSS 4.0, LOW, Tier 4)
            temp_dir = os.getenv("TEMP_DIR", "/tmp/woodtick")
            os.makedirs(temp_dir, exist_ok=True)
            file_path = os.path.join(temp_dir, os.path.basename(object_name))

        # BUG-0093: Path traversal in object_name used to construct local file path (CWE-22, CVSS 6.0, MEDIUM, Tier 3)
        client.fget_object(bucket, object_name, file_path)
        logger.info(f"Downloaded {bucket}/{object_name} -> {file_path}")

        return file_path

    def read_json(self, object_name: str, bucket_name: str = None) -> Any:
        """Read and parse a JSON file from MinIO."""
        client = self.get_conn()
        bucket = bucket_name or self.bucket_name

        response = client.get_object(bucket, object_name)
        data = response.read().decode("utf-8")
        response.close()
        response.release_conn()

        # RH-005: json.loads is safe — this is not eval/exec
        return json.loads(data)

    def write_json(self, object_name: str, data: Any, bucket_name: str = None) -> str:
        """Write JSON data to MinIO."""
        client = self.get_conn()
        bucket = bucket_name or self.bucket_name

        json_bytes = json.dumps(data, indent=2, default=str).encode("utf-8")
        stream = io.BytesIO(json_bytes)

        client.put_object(
            bucket,
            object_name,
            stream,
            length=len(json_bytes),
            content_type="application/json",
        )

        return f"{bucket}/{object_name}"

    def list_objects(
        self,
        prefix: str = "",
        bucket_name: str = None,
        recursive: bool = True,
    ) -> list:
        """List objects in a bucket with optional prefix filter."""
        client = self.get_conn()
        bucket = bucket_name or self.bucket_name

        objects = client.list_objects(bucket, prefix=prefix, recursive=recursive)
        return [
            {
                "name": obj.object_name,
                "size": obj.size,
                "last_modified": str(obj.last_modified),
                "etag": obj.etag,
            }
            for obj in objects
        ]

    def generate_presigned_url(
        self,
        object_name: str,
        bucket_name: str = None,
        expires: int = 3600,
        method: str = "GET",
    ) -> str:
        """Generate a presigned URL for object access."""
        client = self.get_conn()
        bucket = bucket_name or self.bucket_name

        # BUG-0094: No upper bound on presigned URL expiration (CWE-613, CVSS 3.5, LOW, Tier 4)
        # Caller can set expires to any value (e.g., 30 days)
        if method == "GET":
            url = client.presigned_get_object(
                bucket, object_name, expires=timedelta(seconds=expires)
            )
        else:
            url = client.presigned_put_object(
                bucket, object_name, expires=timedelta(seconds=expires)
            )

        return url

    def get_object_hash(self, object_name: str, bucket_name: str = None) -> str:
        """Calculate hash of an object for integrity verification."""
        client = self.get_conn()
        bucket = bucket_name or self.bucket_name

        response = client.get_object(bucket, object_name)
        data = response.read()
        response.close()
        response.release_conn()

        # BUG-0095: MD5 hash for integrity checking — weak hash (CWE-328, CVSS 3.0, LOW, Tier 4)
        return hashlib.md5(data).hexdigest()

    def copy_object(
        self,
        source_object: str,
        dest_object: str,
        source_bucket: str = None,
        dest_bucket: str = None,
    ) -> str:
        """Copy an object within or between buckets."""
        client = self.get_conn()
        src_bucket = source_bucket or self.bucket_name
        dst_bucket = dest_bucket or self.bucket_name

        from minio.commonconfig import CopySource

        client.copy_object(
            dst_bucket,
            dest_object,
            CopySource(src_bucket, source_object),
        )

        logger.info(f"Copied {src_bucket}/{source_object} -> {dst_bucket}/{dest_object}")
        return f"{dst_bucket}/{dest_object}"

    def delete_objects(
        self,
        object_names: list,
        bucket_name: str = None,
    ) -> list:
        """Delete multiple objects from a bucket."""
        client = self.get_conn()
        bucket = bucket_name or self.bucket_name

        from minio.deleteobjects import DeleteObject

        delete_list = [DeleteObject(name) for name in object_names]
        errors = list(client.remove_objects(bucket, delete_list))

        if errors:
            logger.error(f"Errors deleting objects: {errors}")

        return [str(e) for e in errors]
