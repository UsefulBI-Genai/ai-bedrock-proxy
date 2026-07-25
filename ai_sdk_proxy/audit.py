"""
Audit event publisher.

Publishes a structured JSON event to an SNS topic after every LLM call.
The publish is fire-and-forget (non-blocking) — failures are logged but
never propagate to the caller.
"""

import json
import time
import uuid
import logging
import threading
from typing import Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger(__name__)


class AuditPublisher:
    """
    Async SNS publisher for audit events.

    Each publish runs in a daemon thread so it never adds latency
    to the caller's LLM response path.
    """

    def __init__(self, sns_topic_arn: str, region_name: Optional[str] = None):
        if not sns_topic_arn:
            raise ValueError("sns_topic_arn is required for audit publishing")
        self._topic_arn = sns_topic_arn
        self._sns = boto3.client("sns", region_name=region_name)

    def publish(
        self,
        *,
        caller: str,
        identity: dict,
        method: str,
        model_id: Optional[str],
        input_tokens: Optional[int],
        output_tokens: Optional[int],
        latency_ms: float,
        status: str,           # "success" | "error"
        error_code: Optional[str] = None,
    ) -> None:
        """
        Fire-and-forget publish. Runs in a background thread.
        """
        event = {
            "request_id":    str(uuid.uuid4()),
            "timestamp":     time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "caller":        caller,
            "user_id":       identity.get("user_id"),       # sub claim (unique, internal)
            "email":         identity.get("email"),         # human-readable identity
            "username":      identity.get("username"),      # preferred_username or cognito:username
            "idp":           identity.get("idp", "unknown"),
            "method":        method,
            "model_id":      model_id,
            "input_tokens":  input_tokens,
            "output_tokens": output_tokens,
            "latency_ms":    round(latency_ms, 2),
            "status":        status,
            "error_code":    error_code,
        }

        thread = threading.Thread(target=self._send, args=(event,), daemon=True)
        thread.start()

    def _send(self, event: dict) -> None:
        try:
            self._sns.publish(
                TopicArn=self._topic_arn,
                Message=json.dumps(event),
                MessageAttributes={
                    "method": {
                        "DataType": "String",
                        "StringValue": event["method"],
                    },
                    "status": {
                        "DataType": "String",
                        "StringValue": event["status"],
                    },
                },
            )
            logger.debug("Audit event published: request_id=%s", event["request_id"])
        except (BotoCoreError, ClientError) as e:
            # Never let audit failure affect the caller
            logger.error("Failed to publish audit event: %s", e)
