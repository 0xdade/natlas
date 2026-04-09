from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime

import boto3
from botocore.exceptions import ClientError
from django.conf import settings

log = logging.getLogger(__name__)


def _client() -> object:
    return boto3.client(
        "s3",
        endpoint_url=settings.S3_ENDPOINT or None,
        region_name=settings.S3_REGION,
        aws_access_key_id=settings.S3_ACCESS_KEY_ID,
        aws_secret_access_key=settings.S3_SECRET_ACCESS_KEY,
    )


@dataclass
class S3Object:
    data: bytes
    etag: str
    last_modified: datetime


def upload(
    key: str, data: bytes, content_type: str = "application/octet-stream"
) -> None:
    _client().put_object(  # type: ignore[union-attr]
        Bucket=settings.S3_BUCKET,
        Key=key,
        Body=data,
        ContentType=content_type,
    )
    log.debug("Uploaded %d bytes to s3://%s/%s", len(data), settings.S3_BUCKET, key)


def get_object(key: str, if_none_match: str = "") -> S3Object | None:
    """Fetch an object from S3.

    Pass ``if_none_match`` to skip the body when the client already holds the
    current version (S3 returns 304, we return None).
    """
    kwargs: dict[str, object] = {"Bucket": settings.S3_BUCKET, "Key": key}
    if if_none_match:
        kwargs["IfNoneMatch"] = if_none_match
    try:
        resp = _client().get_object(**kwargs)  # type: ignore[union-attr]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "304":  # type: ignore[index]
            return None
        raise
    return S3Object(
        data=resp["Body"].read(),
        etag=resp["ETag"],
        last_modified=resp["LastModified"],
    )
