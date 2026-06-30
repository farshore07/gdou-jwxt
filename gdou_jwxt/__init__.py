"""广东海洋大学教务系统客户端。"""

from .auth import Authenticator
from .client import JwxtClient
from .config import JwxtConfig
from .auto_login import AutoLogin
from .models import AuthResult, AuthStatus, ChallengeType

__all__ = [
    "AutoLogin",
    "Authenticator",
    "AuthResult",
    "AuthStatus",
    "ChallengeType",
    "JwxtClient",
    "JwxtConfig",
]
