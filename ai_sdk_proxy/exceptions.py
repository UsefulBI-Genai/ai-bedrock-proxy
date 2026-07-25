class ProxyAuthError(Exception):
    """Raised when JWT is missing, expired, or invalid."""
    pass


class ProxyConfigError(Exception):
    """Raised when required config (SNS topic, region, etc.) is missing."""
    pass
