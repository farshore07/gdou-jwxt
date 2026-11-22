from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Generic, TypeVar

import requests


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
    IMAGE_CAPTCHA = "image_captcha"
    MFA_REQUIRED = "mfa_required"


class NetworkMode(str, Enum):
    CAMPUS = "campus"
    EXTERNAL = "external"
    AUTO = "auto"

    @classmethod
    def parse(cls, value: "NetworkMode | str | None", default: "NetworkMode | None" = None) -> "NetworkMode":
        if isinstance(value, cls):
            return value
        if value is None:
            return default or cls.CAMPUS
        normalized = str(value).strip().lower()
        mapping = {
            "campus": cls.CAMPUS,
            "direct": cls.CAMPUS,
            "intranet": cls.CAMPUS,
            "external": cls.EXTERNAL,
            "wfw": cls.EXTERNAL,
            "extranet": cls.EXTERNAL,
            "auto": cls.AUTO,
        }
        if normalized in mapping:
            return mapping[normalized]
        raise ValueError(f"不支持的网络环境模式: {value!r}（可选: campus, external, auto）")


class MfaMethod(str, Enum):
    AUTO = "auto"
    WECHAT = "wechat"
    SMS = "sms"

    @property
    def reauth_type(self) -> str:
        if self == MfaMethod.WECHAT:
            return "4"
        if self == MfaMethod.SMS:
            return "3"
        return ""

    @property
    def auth_code_type_name(self) -> str:
        if self == MfaMethod.WECHAT:
            return "reAuthWChatDynamicCodeType"
        if self == MfaMethod.SMS:
            return "reAuthDynamicCodeType"
        return ""

    @property
    def label(self) -> str:
        if self == MfaMethod.WECHAT:
            return "企业微信验证码"
        if self == MfaMethod.SMS:
            return "手机短信验证码"
        return "自动选择"

    @classmethod
    def from_reauth_type(cls, value: str) -> "MfaMethod":
        normalized = (value or "").strip()
        if normalized == "4":
            return cls.WECHAT
        if normalized == "3":
            return cls.SMS
        return cls.AUTO


@dataclass
class CaptchaChallenge:
    image_bytes: bytes
    content_type: str = "image/jpeg"
    username: str = ""
    message: str = ""


@dataclass
class MfaContext:
    """单次二次验证上下文，与发起本次登录的独立 Session 绑定。"""

    username: str
    reauth_user_id: str
    reauth_type: str
    method: MfaMethod
    service: str
    is_multifactor: str = "true"
    is_sleep_account: str = "0"
    network_mode: NetworkMode = NetworkMode.CAMPUS
    available_methods: tuple[MfaMethod, ...] = ()
    code_sent: bool = False
    countdown: int = 0
    message: str = ""
    created_at: float = field(default_factory=time.monotonic)
    consumed: bool = False
    _session: requests.Session | None = field(default=None, repr=False, compare=False)
    _owner_id: int | None = field(default=None, repr=False, compare=False)


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


def _text(data: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = data.get(key)
        if value is not None:
            return str(value)
    return ""


def _int(data: dict[str, Any], key: str) -> int:
    value = data.get(key)
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


T = TypeVar("T")


@dataclass
class PageResult(Generic[T]):
    items: list[T]
    total_count: int = 0
    total_page: int = 0
    current_page: int = 1
    page_size: int = 15
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any], item_type: type[T]) -> "PageResult[T]":
        raw_items = data.get("items")
        if not isinstance(raw_items, list):
            raw_items = []
        items = [
            item_type.from_dict(item)
            for item in raw_items
            if isinstance(item, dict) and hasattr(item_type, "from_dict")
        ]
        return cls(
            items=items,
            total_count=_int(data, "totalCount"),
            total_page=_int(data, "totalPage"),
            current_page=_int(data, "currentPage") or 1,
            page_size=_int(data, "pageSize") or _int(data, "showCount") or 15,
            raw=data,
        )


@dataclass
class GradeRecord:
    course_code: str = ""
    course_name: str = ""
    academic_year: str = ""
    term: str = ""
    credit: str = ""
    grade: str = ""
    grade_point: str = ""
    course_nature: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "GradeRecord":
        return cls(
            course_code=_text(data, "kch", "kch_id"),
            course_name=_text(data, "kcmc"),
            academic_year=_text(data, "xnmmc", "xnm"),
            term=_text(data, "xqmmc", "xqm"),
            credit=_text(data, "xf"),
            grade=_text(data, "cj", "bfzcj", "zcj"),
            grade_point=_text(data, "jd"),
            course_nature=_text(data, "kcxzmc", "kcxz"),
            raw=data,
        )


@dataclass
class TimetableCourse:
    course_code: str = ""
    course_name: str = ""
    teacher: str = ""
    weekday: str = ""
    weekday_name: str = ""
    periods: str = ""
    weeks: str = ""
    classroom: str = ""
    campus: str = ""
    credit: str = ""
    teaching_class: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TimetableCourse":
        return cls(
            course_code=_text(data, "kch", "kch_id"),
            course_name=_text(data, "kcmc"),
            teacher=_text(data, "xm"),
            weekday=_text(data, "xqj"),
            weekday_name=_text(data, "xqjmc"),
            periods=_text(data, "jc", "jcs"),
            weeks=_text(data, "zcd", "zcmc"),
            classroom=_text(data, "cdmc"),
            campus=_text(data, "xqmc"),
            credit=_text(data, "xf"),
            teaching_class=_text(data, "jxbmc"),
            raw=data,
        )


@dataclass
class TimetableResult:
    courses: list[TimetableCourse] = field(default_factory=list)
    student_info: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TimetableResult":
        raw_courses = data.get("kbList")
        if not isinstance(raw_courses, list):
            raw_courses = []
        student_info = data.get("xsxx")
        if not isinstance(student_info, dict):
            student_info = {}
        return cls(
            courses=[TimetableCourse.from_dict(item) for item in raw_courses if isinstance(item, dict)],
            student_info=student_info,
            raw=data,
        )


@dataclass
class ExamScheduleRecord:
    course_code: str = ""
    course_name: str = ""
    exam_name: str = ""
    exam_time: str = ""
    classroom: str = ""
    exam_place: str = ""
    campus: str = ""
    exam_method: str = ""
    assessment_method: str = ""
    credit: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ExamScheduleRecord":
        return cls(
            course_code=_text(data, "kch"),
            course_name=_text(data, "kcmc"),
            exam_name=_text(data, "ksmc"),
            exam_time=_text(data, "kssj", "sksj"),
            classroom=_text(data, "cdmc", "cdjc"),
            exam_place=_text(data, "jxdd"),
            campus=_text(data, "cdxqmc", "xqmc"),
            exam_method=_text(data, "ksfs"),
            assessment_method=_text(data, "khfs"),
            credit=_text(data, "xf"),
            raw=data,
        )
