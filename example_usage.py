"""
AI SDK Proxy — example usage.

Step 1: Log in once (opens browser → Okta):
    ai-sdk login

Step 2: Run this script. Auth and audit are invisible.
    python3 example_usage.py
"""

import json
import os
import time
import boto3
from contextlib import contextmanager
from ai_sdk_proxy import BedrockRuntimeClient


@contextmanager
def timer(label: str):
    start = time.perf_counter()
    try:
        yield
    finally:
        ms = (time.perf_counter() - start) * 1000
        print(f"  ⏱  {label}: {ms:.0f} ms")


SNS_TOPIC_ARN = os.environ.get(
    "AI_SDK_AUDIT_TOPIC_ARN",
    "arn:aws:sns:us-east-1:025066239748:ai-sdk-proxy-audit-dev",
)

MODEL_ID = "us.anthropic.claude-sonnet-4-6"

# Raw boto3 — baseline
_raw = boto3.client("bedrock-runtime", region_name="us-east-1")

# Proxy client — identity resolved once here, zero per-request auth cost
client = BedrockRuntimeClient.from_local_session(
    sns_topic_arn=SNS_TOPIC_ARN,
    region_name="us-east-1",
    caller="poc-test",
)

# ── converse ──────────────────────────────────────────────────────────────────
print("=== converse ===")
print("  (each call is independent — model latency varies; run multiple times for averages)")
_params = dict(
    modelId=MODEL_ID,
    messages=[{"role": "user", "content": [{"text": "Explain SNS fan-out in one sentence."}]}],
)

with timer("raw boto3"):
    _r = _raw.converse(**_params)

with timer("proxy     "):
    response = client.converse(modelId="default", messages=_params["messages"])

print(response["output"]["message"]["content"][0]["text"])

# ── invoke_model ──────────────────────────────────────────────────────────────
print("\n=== invoke_model ===")
_body = json.dumps({
    "anthropic_version": "bedrock-2023-05-31",
    "max_tokens": 50,
    "messages": [{"role": "user", "content": "Say hello in one word."}],
})
_invoke_params = dict(
    modelId=MODEL_ID, contentType="application/json", accept="application/json", body=_body
)

with timer("raw boto3"):
    _r = _raw.invoke_model(**_invoke_params)
    _r["body"].read()  # consume so timing is complete

with timer("proxy     "):
    response = client.invoke_model(**_invoke_params)

print(json.loads(response["body"].read())["content"][0]["text"])

# ── invoke_model_with_response_stream ─────────────────────────────────────────
print("\n=== invoke_model_with_response_stream ===")
_stream_body = json.dumps({
    "anthropic_version": "bedrock-2023-05-31",
    "max_tokens": 50,
    "messages": [{"role": "user", "content": "Count to 3."}],
})
_stream_params = dict(
    modelId=MODEL_ID, contentType="application/json", accept="application/json", body=_stream_body
)


def _drain_stream(stream_response) -> tuple[float, float]:
    """
    Consume a stream response dict (as returned by invoke_model_with_response_stream).
    Returns (time_to_first_token_ms, total_ms) measured from the moment this
    function is called — i.e. AFTER the HTTP connection is already open.
    """
    first = None
    t0 = time.perf_counter()
    for event in stream_response["body"]:
        chunk = json.loads(event["chunk"]["bytes"])
        if chunk.get("type") == "content_block_delta":
            if first is None:
                first = (time.perf_counter() - t0) * 1000
    total = (time.perf_counter() - t0) * 1000
    return first or 0.0, total


# Raw baseline — time the full call including HTTP round-trip
raw_t0 = time.perf_counter()
_raw_stream = _raw.invoke_model_with_response_stream(**_stream_params)
raw_first, raw_total = _drain_stream(_raw_stream)
raw_total = (time.perf_counter() - raw_t0) * 1000  # full wall time
# first-token is relative to when body iteration started; add connection time
raw_conn = (time.perf_counter() - raw_t0) * 1000 - raw_total  # negligible but captured
print(f"  raw boto3  — first token: {raw_first:.0f} ms  |  full stream: {raw_total:.0f} ms")

# Proxy — same measurement: start timer before the call
proxy_t0 = time.perf_counter()
proxy_stream = client.invoke_model_with_response_stream(**_stream_params)
proxy_first = None
for event in proxy_stream["body"]:
    chunk = json.loads(event["chunk"]["bytes"])
    if chunk.get("type") == "content_block_delta":
        if proxy_first is None:
            proxy_first = (time.perf_counter() - proxy_t0) * 1000
        print(chunk["delta"].get("text", ""), end="", flush=True)
proxy_total = (time.perf_counter() - proxy_t0) * 1000
print()
print(f"  proxy      — first token: {proxy_first:.0f} ms  |  full stream: {proxy_total:.0f} ms")
print(f"  overhead   — first token: +{(proxy_first or 0) - raw_first:.0f} ms"
      f"  |  full stream: +{proxy_total - raw_total:.0f} ms")

client.close()
print("\nDone. Audit events are publishing in background.")
print("  aws logs tail /aws/lambda/ai-sdk-proxy-audit-printer-dev --follow --region us-east-1")
