from .client import BedrockRuntimeClient

def __getattr__(name):
    if name == "AISdkSession":
        from .session import AISdkSession
        return AISdkSession
    raise AttributeError(f"module 'ai_sdk_proxy' has no attribute {name!r}")

__all__ = ["BedrockRuntimeClient", "AISdkSession"]
__version__ = "0.1.0"
