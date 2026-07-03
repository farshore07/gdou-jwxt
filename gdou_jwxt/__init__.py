"""广东海洋大学教务系统客户端。"""

from .auth import Authenticator
from .client import JwxtClient
from .config import JwxtConfig
from .cookie_store import CookieStore
from .auto_login import AutoLogin
from .models import (
    AuthResult,
    AuthStatus,
    ChallengeType,
    ExamScheduleRecord,
    GradeRecord,
    PageResult,
    TimetableCourse,
    TimetableResult,
)

__all__ = [
    "AutoLogin",
    "Authenticator",
    "AuthResult",
    "AuthStatus",
    "ChallengeType",
    "CookieStore",
    "ExamScheduleRecord",
    "GradeRecord",
    "JwxtClient",
    "JwxtConfig",
    "PageResult",
    "TimetableCourse",
    "TimetableResult",
]
