"""Live collection. The only module that touches AWS, and it is imported lazily."""

from __future__ import annotations

import datetime as dt
import json
from typing import Any, Dict, List, Optional

from .model import PAYLOAD_VERSION


def collect(profile: Optional[str] = None, region: Optional[str] = None) -> Dict[str, Any]:
    """Build the payload the rule engine consumes: one dict, no AWS types left in it.

    Three calls per secret at most: the paginated ``list_secrets``, ``describe_secret`` for
    the rotation and access metadata that the list call does not return reliably, and
    ``get_resource_policy``. Everything is serialised through ``json`` immediately so a
    ``--dump-json`` file and a live run are the same input to the rules.
    """
    import boto3  # imported here so the rules, the tests and --from-json need no boto3
    from botocore.exceptions import ClientError

    session = boto3.Session(profile_name=profile, region_name=region)
    client = session.client("secretsmanager")

    account = None
    try:
        account = session.client("sts").get_caller_identity()["Account"]
    except Exception:  # pragma: no cover - credentials may not allow sts
        pass

    listed = _list_secrets(client)
    secrets: List[Dict[str, Any]] = []
    for item in listed:
        secret_id = item.get("ARN") or item.get("Name")
        described: Dict[str, Any] = dict(item)
        try:
            described.update(client.describe_secret(SecretId=secret_id))
        except ClientError as exc:  # pragma: no cover - permission shaped
            described["_describe_error"] = _error_code(exc)
        described.pop("ResponseMetadata", None)
        described["ResourcePolicy"] = _resource_policy(client, secret_id, ClientError)
        secrets.append(described)

    payload = {
        "payload_version": PAYLOAD_VERSION,
        "account": account,
        "region": client.meta.region_name,
        "collected_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "secrets": secrets,
    }
    # Round-trip through JSON so datetimes become strings exactly once, here.
    return json.loads(json.dumps(payload, default=str))


def _list_secrets(client: Any) -> List[Dict[str, Any]]:
    kwargs: Dict[str, Any] = {"IncludePlannedDeletion": True}
    while True:
        try:
            paginator = client.get_paginator("list_secrets")
            out: List[Dict[str, Any]] = []
            for page in paginator.paginate(**kwargs):
                out.extend(page.get("SecretList", []))
            return out
        except Exception as exc:  # pragma: no cover - older botocore lacks the flag
            if "IncludePlannedDeletion" in kwargs and "IncludePlannedDeletion" in str(exc):
                kwargs.pop("IncludePlannedDeletion")
                continue
            raise


def _resource_policy(client: Any, secret_id: str, client_error: Any) -> Optional[Any]:
    try:
        response = client.get_resource_policy(SecretId=secret_id)
    except client_error as exc:  # pragma: no cover - permission shaped
        code = _error_code(exc)
        return {"_error": code} if code != "ResourceNotFoundException" else None
    body = response.get("ResourcePolicy")
    if not body:
        return None
    try:
        return json.loads(body)
    except ValueError:
        return body


def _error_code(exc: Any) -> str:
    return (getattr(exc, "response", {}) or {}).get("Error", {}).get("Code", "Unknown")
