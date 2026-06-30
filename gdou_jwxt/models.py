from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AuthStatus(str, Enum):
    SUCCESS = "success"
    NEED_MANUAL_VERIFICATION = "need_manual_verification"
    INVALID_CREDENTIALS = "invalid_credentials"
    SESSION_EXPIRED = "session_expired"
    NETWORK_ERROR = "network_error"
    AUTHENTICATION_REQUIRED = "authentication_required"
    VERIFICATION_INCOMPLETE = "verification_incomplete"
    UNKNOWN_ERROR = "unknown_error"


class ChallengeType(str, Enum):
    SLIDER_CAPTCHA = "slider_captcha"
    SECONDARY_VERIFICATION = "secondary_verification"


@dataclass
class AuthResult:
    status: AuthStatus
    message: str = ""
    challenge_type: ChallengeType | None = None
    url: str | None = None
    data: Any = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status == AuthStatus.SUCCESS
