"""
Unit tests for BedrockRuntimeClient proxy.

Uses mocks for Bedrock and SNS — no real AWS calls made.
Run: pytest tests/
"""

import json
import time
import base64
import unittest
from unittest.mock import MagicMock, patch, call

from ai_sdk_proxy import BedrockRuntimeClient
from ai_sdk_proxy.exceptions import ProxyAuthError, ProxyConfigError
from ai_sdk_proxy.auth import TokenManager, validate_and_extract


# ── JWT helpers ────────────────────────────────────────────────────

def _make_jwt(sub="user-123", email="test@example.com", exp_offset=3600):
    """Build a minimal JWT with a real base64 payload (no signature)."""
    import time as t
    payload = {
        "sub": sub,
        "email": email,
        "exp": int(t.time()) + exp_offset,
        "cognito:username": "testuser",
    }
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).rstrip(b"=").decode()
    return f"header.{payload_b64}.signature"


def _expired_jwt():
    return _make_jwt(exp_offset=-3600)  # expired 1hr ago


# ── Auth tests ─────────────────────────────────────────────────────

class TestTokenManager(unittest.TestCase):

    def test_valid_jwt_returns_identity(self):
        jwt = _make_jwt()
        mgr = TokenManager(jwt=jwt)
        identity = mgr.get_identity()
        self.assertEqual(identity["user_id"], "user-123")
        self.assertEqual(identity["email"], "test@example.com")

    def test_expired_jwt_raises_without_provider(self):
        mgr = TokenManager(jwt=_expired_jwt())
        with self.assertRaises(ProxyAuthError):
            mgr.get_identity()

    def test_expired_jwt_refreshes_with_provider(self):
        fresh_jwt = _make_jwt(sub="user-456")
        provider = MagicMock(return_value=fresh_jwt)
        mgr = TokenManager(jwt=_expired_jwt(), token_provider=provider)
        identity = mgr.get_identity()
        provider.assert_called_once()
        self.assertEqual(identity["user_id"], "user-456")

    def test_no_jwt_no_provider_raises(self):
        with self.assertRaises(ProxyAuthError):
            TokenManager()

    def test_missing_sns_raises(self):
        jwt = _make_jwt()
        with self.assertRaises(ProxyConfigError):
            BedrockRuntimeClient(jwt=jwt)  # no sns_topic_arn, no env var


# ── Client proxy tests ─────────────────────────────────────────────

class TestBedrockRuntimeClient(unittest.TestCase):

    def _make_client(self, jwt=None):
        """Return a client with mocked boto3 and SNS."""
        jwt = jwt or _make_jwt()
        with patch("ai_sdk_proxy.client.boto3") as mock_boto3, \
             patch("ai_sdk_proxy.audit.boto3") as mock_audit_boto3:

            mock_bedrock = MagicMock()
            mock_boto3.client.return_value = mock_bedrock
            mock_sns = MagicMock()
            mock_audit_boto3.client.return_value = mock_sns

            client = BedrockRuntimeClient(
                jwt=jwt,
                sns_topic_arn="arn:aws:sns:us-east-1:123456789012:ai-audit",
                region_name="us-east-1",
                caller="test-suite",
            )
            client._bedrock = mock_bedrock
            client._audit._sns = mock_sns
            return client, mock_bedrock, mock_sns

    def test_converse_forwards_kwargs(self):
        client, mock_bedrock, _ = self._make_client()
        mock_bedrock.converse.return_value = {
            "output": {"message": {"content": [{"text": "hi"}]}},
            "usage": {"inputTokens": 10, "outputTokens": 5},
        }
        resp = client.converse(
            modelId="default",
            messages=[{"role": "user", "content": [{"text": "Hello"}]}],
        )
        # modelId alias resolved
        mock_bedrock.converse.assert_called_once()
        call_kwargs = mock_bedrock.converse.call_args[1]
        self.assertEqual(call_kwargs["modelId"], "anthropic.claude-sonnet-4-5")
        self.assertEqual(resp["output"]["message"]["content"][0]["text"], "hi")

    def test_invoke_model_forwards_kwargs(self):
        client, mock_bedrock, _ = self._make_client()
        mock_bedrock.invoke_model.return_value = {"body": MagicMock()}
        client.invoke_model(
            modelId="anthropic.claude-haiku-20240307",
            body=b"{}",
            contentType="application/json",
        )
        mock_bedrock.invoke_model.assert_called_once()

    def test_model_alias_resolves(self):
        client, mock_bedrock, _ = self._make_client()
        mock_bedrock.converse.return_value = {"usage": {}}
        client.converse(modelId="claude-haiku", messages=[])
        call_kwargs = mock_bedrock.converse.call_args[1]
        self.assertEqual(call_kwargs["modelId"], "anthropic.claude-haiku-20240307")

    def test_unknown_model_passes_through(self):
        client, mock_bedrock, _ = self._make_client()
        mock_bedrock.converse.return_value = {"usage": {}}
        client.converse(modelId="my-custom-model-id", messages=[])
        call_kwargs = mock_bedrock.converse.call_args[1]
        self.assertEqual(call_kwargs["modelId"], "my-custom-model-id")

    def test_bedrock_error_re_raised(self):
        from botocore.exceptions import ClientError
        client, mock_bedrock, _ = self._make_client()
        mock_bedrock.converse.side_effect = ClientError(
            {"Error": {"Code": "ThrottlingException", "Message": "Rate exceeded"}},
            "Converse",
        )
        with self.assertRaises(ClientError):
            client.converse(modelId="default", messages=[])

    def test_context_manager(self):
        client, mock_bedrock, _ = self._make_client()
        mock_bedrock.converse.return_value = {"usage": {}}
        with client as c:
            c.converse(modelId="default", messages=[])
        mock_bedrock.close.assert_called_once()

    def test_can_paginate_delegated(self):
        client, mock_bedrock, _ = self._make_client()
        mock_bedrock.can_paginate.return_value = True
        result = client.can_paginate("list_async_invokes")
        mock_bedrock.can_paginate.assert_called_once_with("list_async_invokes")
        self.assertTrue(result)


if __name__ == "__main__":
    unittest.main()
