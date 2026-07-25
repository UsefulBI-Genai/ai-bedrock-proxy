"""
BedrockRuntimeClient — AI SDK Proxy

Drop-in replacement for boto3.client("bedrock-runtime").
Same method names, same parameters, same return shapes.

The only difference is the constructor, which requires a Cognito JWT
or a token_provider callable for identity and audit.

Latency design:
  - Identity is resolved ONCE at construction and cached. Per-request auth
    cost is a dict lookup — no JWT decode, no JWKS round-trip.
  - Audit (SNS publish) is always fire-and-forget in a background thread.
    The caller gets the Bedrock response back before SNS is even contacted.
  - invoke_model body is returned to the caller immediately; token-count
    extraction and audit publish happen in a background thread.

Usage:
    from ai_sdk_proxy import BedrockRuntimeClient

    client = BedrockRuntimeClient(
        token_provider=my_cognito_refresh_fn,
        sns_topic_arn="arn:aws:sns:us-east-1:123456789012:ai-audit",
        region_name="us-east-1",
    )

    # All calls identical to boto3 after this point
    response = client.converse(modelId="...", messages=[...])
"""

import io
import json
import os
import threading
import time
import logging
from pathlib import Path
from typing import Callable, Optional

import boto3

from .auth import TokenManager
from .audit import AuditPublisher
from .exceptions import ProxyAuthError, ProxyConfigError

logger = logging.getLogger(__name__)

# Default audit SNS topic — used when no sns_topic_arn is passed.
# Override via AI_SDK_AUDIT_TOPIC_ARN env var or pass explicitly to the constructor.
_DEFAULT_AUDIT_TOPIC_ARN = "arn:aws:sns:us-west-2:025066239748:ai-sdk-proxy-audit"

# Friendly model aliases → Bedrock inference profile IDs
_MODEL_ALIASES = {
    "default":        "us.anthropic.claude-sonnet-4-6",
    "claude-sonnet":  "us.anthropic.claude-sonnet-4-6",
    "claude-haiku":   "us.anthropic.claude-haiku-4-5-20251001-v1:0",
    "claude-opus":    "us.anthropic.claude-opus-4-1-20250805-v1:0",
}


def _resolve_model(model_id: str) -> str:
    return _MODEL_ALIASES.get(model_id, model_id)


class BedrockRuntimeClient:
    """
    Proxy client with identical interface to boto3 bedrock-runtime.

    Constructor params:
        jwt             : str      — ID token from Cognito or Okta
        token_provider  : callable — called with no args, returns a fresh JWT
        jwks_url        : str      — optional explicit JWKS URL (auto-detected from 'iss')
        sns_topic_arn   : str      — SNS topic ARN for audit events
                                     Falls back to env var AI_SDK_AUDIT_TOPIC_ARN
        region_name     : str      — AWS region (default: us-east-1)
        caller          : str      — identifies the calling service in audit logs
    """

    def __init__(
        self,
        *,
        jwt: Optional[str] = None,
        token_provider: Optional[Callable] = None,
        jwks_url: Optional[str] = None,
        sns_topic_arn: Optional[str] = None,
        region_name: str = "us-east-1",
        caller: str = "unknown",
    ):
        self._token_manager = TokenManager(
            jwt=jwt, token_provider=token_provider, jwks_url=jwks_url
        )
        self._caller = caller
        self._region = region_name

        topic_arn = sns_topic_arn or os.environ.get("AI_SDK_AUDIT_TOPIC_ARN") or _DEFAULT_AUDIT_TOPIC_ARN
        self._audit = AuditPublisher(sns_topic_arn=topic_arn, region_name=region_name)

        # Resolve identity once at construction — cached for the lifetime of the client.
        # Token refresh (if needed) happens here, not on the hot path.
        self._identity: dict = self._token_manager.get_identity()
        self._identity_token: str = self._token_manager.get_valid_token()

        # Underlying boto3 bedrock-runtime client
        self._bedrock = boto3.client("bedrock-runtime", region_name=region_name)

    # ── identity helpers ───────────────────────────────────────────────────────

    def _get_identity(self) -> dict:
        """
        Return cached identity. Refreshes only when the underlying token has
        actually changed (e.g. silent refresh happened between calls).
        Zero network I/O on the hot path.
        """
        try:
            current_token = self._token_manager.get_valid_token()
        except ProxyAuthError:
            return self._identity  # best-effort: use last known identity

        if current_token != self._identity_token:
            # Token was silently refreshed — update cached identity
            self._identity = self._token_manager.get_identity()
            self._identity_token = current_token

        return self._identity

    # ── audit helpers ──────────────────────────────────────────────────────────

    def _emit_async(
        self,
        method: str,
        model_id: Optional[str],
        start: float,
        status: str = "success",
        error_code: Optional[str] = None,
        input_tokens: Optional[int] = None,
        output_tokens: Optional[int] = None,
    ) -> None:
        """
        Fire-and-forget audit publish. Returns immediately — SNS call happens
        in a background thread so it never adds latency to the response path.
        """
        latency_ms = (time.time() - start) * 1000
        identity = self._get_identity()  # dict lookup — no I/O

        self._audit.publish(
            caller=self._caller,
            identity=identity,
            method=method,
            model_id=model_id,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            latency_ms=latency_ms,
            status=status,
            error_code=error_code,
        )

    # ── LLM invocation methods ─────────────────────────────────────────────────

    def invoke_model(self, **kwargs):
        """
        Identical to boto3 bedrock-runtime invoke_model().

        Body is returned to the caller immediately (re-wrapped as BytesIO).
        Token-count extraction + audit publish happen in a background thread
        so the caller sees zero overhead beyond the raw Bedrock call.
        """
        kwargs["modelId"] = _resolve_model(kwargs.get("modelId", ""))
        start = time.time()
        try:
            response = self._bedrock.invoke_model(**kwargs)

            # Read body once, re-wrap so caller can still call .read()
            raw_body = response["body"].read()
            response["body"] = io.BytesIO(raw_body)

            # Parse tokens and emit audit entirely in background
            model_id = kwargs["modelId"]
            emit_fn  = self._emit_async

            def _bg():
                try:
                    body_json     = json.loads(raw_body)
                    usage         = body_json.get("usage", {})
                    input_tokens  = usage.get("input_tokens")
                    output_tokens = usage.get("output_tokens")
                except Exception:
                    input_tokens = output_tokens = None
                emit_fn("invoke_model", model_id, start,
                        input_tokens=input_tokens, output_tokens=output_tokens)

            threading.Thread(target=_bg, daemon=True).start()
            return response

        except Exception as e:
            self._emit_async("invoke_model", kwargs.get("modelId"), start,
                             status="error", error_code=type(e).__name__)
            raise

    def invoke_model_with_response_stream(self, **kwargs):
        """
        Identical to boto3 bedrock-runtime invoke_model_with_response_stream().

        Chunks are yielded to the caller with zero proxy overhead.
        Token counts are collected while streaming; audit fires after the
        last chunk is consumed — completely transparent to the caller.
        """
        kwargs["modelId"] = _resolve_model(kwargs.get("modelId", ""))
        start    = time.time()
        model_id = kwargs["modelId"]
        emit_fn  = self._emit_async

        try:
            response = self._bedrock.invoke_model_with_response_stream(**kwargs)
        except Exception as e:
            self._emit_async("invoke_model_with_response_stream", model_id, start,
                             status="error", error_code=type(e).__name__)
            raise

        original_body = response["body"]

        class _TokenInterceptStream:
            """
            Thin pass-through wrapper. Collects token counts from stream
            events and fires the audit log after the last chunk — no
            buffering, no added latency per chunk.
            """
            def __iter__(self_inner):
                input_tokens = output_tokens = None
                try:
                    for event in original_body:
                        chunk_bytes = event.get("chunk", {}).get("bytes", b"")
                        if chunk_bytes:
                            try:
                                chunk_data = json.loads(chunk_bytes)
                                etype = chunk_data.get("type", "")
                                if etype == "message_start":
                                    u = chunk_data.get("message", {}).get("usage", {})
                                    input_tokens = u.get("input_tokens", input_tokens)
                                elif etype == "message_delta":
                                    u = chunk_data.get("usage", {})
                                    output_tokens = u.get("output_tokens", output_tokens)
                            except Exception:
                                pass
                        yield event  # ← caller gets chunk immediately
                finally:
                    # Stream done — emit audit in background (already non-blocking
                    # inside AuditPublisher, but be explicit here too)
                    threading.Thread(
                        target=emit_fn,
                        kwargs=dict(
                            method="invoke_model_with_response_stream",
                            model_id=model_id,
                            start=start,
                            input_tokens=input_tokens,
                            output_tokens=output_tokens,
                        ),
                        daemon=True,
                    ).start()

        response["body"] = _TokenInterceptStream()
        return response

    def converse(self, **kwargs):
        """
        Identical to boto3 bedrock-runtime converse().
        Audit fires in background after the response is returned to caller.
        """
        kwargs["modelId"] = _resolve_model(kwargs.get("modelId", ""))
        start = time.time()
        try:
            response = self._bedrock.converse(**kwargs)
            # Capture usage before returning so the background thread has it
            usage         = (response.get("usage") or {})
            input_tokens  = usage.get("inputTokens")
            output_tokens = usage.get("outputTokens")
            model_id      = kwargs["modelId"]
            emit_fn       = self._emit_async

            threading.Thread(
                target=emit_fn,
                kwargs=dict(
                    method="converse",
                    model_id=model_id,
                    start=start,
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                ),
                daemon=True,
            ).start()
            return response  # ← returned before SNS is contacted
        except Exception as e:
            self._emit_async("converse", kwargs.get("modelId"), start,
                             status="error", error_code=type(e).__name__)
            raise

    def converse_stream(self, **kwargs):
        """
        Identical to boto3 bedrock-runtime converse_stream().
        """
        kwargs["modelId"] = _resolve_model(kwargs.get("modelId", ""))
        start = time.time()
        try:
            response = self._bedrock.converse_stream(**kwargs)
            model_id = kwargs["modelId"]
            emit_fn  = self._emit_async
            threading.Thread(
                target=emit_fn,
                kwargs=dict(method="converse_stream", model_id=model_id, start=start),
                daemon=True,
            ).start()
            return response
        except Exception as e:
            self._emit_async("converse_stream", kwargs.get("modelId"), start,
                             status="error", error_code=type(e).__name__)
            raise

    # ── Guardrails ─────────────────────────────────────────────────────────────

    def apply_guardrail(self, **kwargs):
        """Identical to boto3 bedrock-runtime apply_guardrail()."""
        start = time.time()
        try:
            response = self._bedrock.apply_guardrail(**kwargs)
            emit_fn = self._emit_async
            threading.Thread(
                target=emit_fn,
                kwargs=dict(method="apply_guardrail", model_id=None, start=start),
                daemon=True,
            ).start()
            return response
        except Exception as e:
            self._emit_async("apply_guardrail", None, start,
                             status="error", error_code=type(e).__name__)
            raise

    def invoke_guardrail_checks(self, **kwargs):
        """Identical to boto3 bedrock-runtime invoke_guardrail_checks()."""
        start = time.time()
        try:
            response = self._bedrock.invoke_guardrail_checks(**kwargs)
            emit_fn = self._emit_async
            threading.Thread(
                target=emit_fn,
                kwargs=dict(method="invoke_guardrail_checks", model_id=None, start=start),
                daemon=True,
            ).start()
            return response
        except Exception as e:
            self._emit_async("invoke_guardrail_checks", None, start,
                             status="error", error_code=type(e).__name__)
            raise

    # ── Token counting ─────────────────────────────────────────────────────────

    def count_tokens(self, **kwargs):
        """Identical to boto3 bedrock-runtime count_tokens()."""
        kwargs["modelId"] = _resolve_model(kwargs.get("modelId", ""))
        start = time.time()
        try:
            response = self._bedrock.count_tokens(**kwargs)
            model_id = kwargs["modelId"]
            emit_fn  = self._emit_async
            threading.Thread(
                target=emit_fn,
                kwargs=dict(method="count_tokens", model_id=model_id, start=start),
                daemon=True,
            ).start()
            return response
        except Exception as e:
            self._emit_async("count_tokens", kwargs.get("modelId"), start,
                             status="error", error_code=type(e).__name__)
            raise

    # ── Async invocations ──────────────────────────────────────────────────────

    def start_async_invoke(self, **kwargs):
        """Identical to boto3 bedrock-runtime start_async_invoke()."""
        kwargs["modelId"] = _resolve_model(kwargs.get("modelId", ""))
        start = time.time()
        try:
            response = self._bedrock.start_async_invoke(**kwargs)
            model_id = kwargs["modelId"]
            emit_fn  = self._emit_async
            threading.Thread(
                target=emit_fn,
                kwargs=dict(method="start_async_invoke", model_id=model_id, start=start),
                daemon=True,
            ).start()
            return response
        except Exception as e:
            self._emit_async("start_async_invoke", kwargs.get("modelId"), start,
                             status="error", error_code=type(e).__name__)
            raise

    def get_async_invoke(self, **kwargs):
        """Identical to boto3 bedrock-runtime get_async_invoke()."""
        return self._bedrock.get_async_invoke(**kwargs)

    def list_async_invokes(self, **kwargs):
        """Identical to boto3 bedrock-runtime list_async_invokes()."""
        return self._bedrock.list_async_invokes(**kwargs)

    # ── Pagination / waiters ───────────────────────────────────────────────────

    def can_paginate(self, operation_name: str) -> bool:
        """Identical to boto3 can_paginate()."""
        return self._bedrock.can_paginate(operation_name)

    def get_paginator(self, operation_name: str):
        """Identical to boto3 get_paginator()."""
        return self._bedrock.get_paginator(operation_name)

    def get_waiter(self, waiter_name: str):
        """Identical to boto3 get_waiter()."""
        return self._bedrock.get_waiter(waiter_name)

    # ── Cleanup ────────────────────────────────────────────────────────────────

    def close(self) -> None:
        """Identical to boto3 close(). Closes the underlying HTTP connection."""
        self._bedrock.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    # ── Alternate constructors ─────────────────────────────────────────────────

    @classmethod
    def from_local_session(
        cls,
        sns_topic_arn: Optional[str] = None,
        region_name: str = "us-east-1",
        caller: str = "cli",
        session_file: Optional[str] = None,
    ) -> "BedrockRuntimeClient":
        """
        CLI convenience constructor.
        Reads cached tokens from ~/.ai_sdk/session.json (written by `ai-sdk login`).
        Identity is resolved once here; auto-refreshes silently when token expires.

        sns_topic_arn is optional — defaults to the platform audit topic.
        Run `ai-sdk login` first.
        """
        from .session import AISdkSession
        sdk_session = AISdkSession()
        sdk_session.get_token()  # fail fast if no session exists

        return cls(
            token_provider=sdk_session.get_token,
            sns_topic_arn=sns_topic_arn,  # None → falls back to _DEFAULT_AUDIT_TOPIC_ARN
            region_name=region_name,
            caller=caller,
        )
