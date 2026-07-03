from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, TypeVar


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
class PageResult:
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
