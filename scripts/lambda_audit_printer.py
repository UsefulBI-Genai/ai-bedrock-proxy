"""
audit_printer — Lambda function code

Subscribes to the AI SDK Proxy SNS audit topic.
Prints (logs) each audit event to CloudWatch Logs.

Deployed automatically by setup_infra.py.
"""

import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def handler(event, context):
    for record in event.get("Records", []):
        raw = record.get("Sns", {}).get("Message", "{}")
        try:
            audit = json.loads(raw)
        except json.JSONDecodeError:
            audit = {"raw": raw}

        logger.info(
            "AUDIT | request_id=%(request_id)s caller=%(caller)s "
            "email=%(email)s user_id=%(user_id)s idp=%(idp)s "
            "model=%(model_id)s method=%(method)s "
            "status=%(status)s input_tokens=%(input_tokens)s "
            "output_tokens=%(output_tokens)s latency_ms=%(latency_ms)s",
            {k: audit.get(k, "-") for k in [
                "request_id", "caller", "email", "user_id", "idp",
                "model_id", "method", "status", "input_tokens", "output_tokens", "latency_ms",
            ]},
        )
    return {"statusCode": 200}
