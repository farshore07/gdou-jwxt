from __future__ import annotations

from typing import Any

import requests

from .auth import Authenticator
from .config import JwxtConfig
from .models import AuthResult, AuthStatus, ExamScheduleRecord, GradeRecord, PageResult, TimetableResult


def _academic_year_code(academic_year: str) -> str:
    return academic_year.split("-", 1)[0].strip()


class JwxtClient:
    def __init__(
        self,
        username: str | None = None,
        password: str | None = None,
        config: JwxtConfig | None = None,
        session: requests.Session | None = None,
        authenticator: Authenticator | None = None,
    ) -> None:
        self.config = config or JwxtConfig()
        self.username = username
        self.password = password
        self.session = session or requests.Session()
        self.session.headers.update(self.config.headers)
        self.authenticator = authenticator or Authenticator(self.config, self.session)

    def ensure_authenticated(self) -> AuthResult:
        result = self.authenticator.validate_session()
        if result.ok:
            return result
        if not self.username or not self.password:
            return AuthResult(AuthStatus.AUTHENTICATION_REQUIRED, "缺少账号或密码", url=result.url)
        return self.authenticator.login(self.username, self.password)

    def request_protected(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> tuple[AuthResult, requests.Response | None]:
        auth = self.ensure_authenticated()
        if not auth.ok:
            return auth, None
        response = self.session.request(method, url, timeout=self.config.timeout, **kwargs)
        if response.url and "login" in response.url.lower():
            return AuthResult(AuthStatus.AUTHENTICATION_REQUIRED, "请求被重定向到登录页", url=response.url), None
        return AuthResult(AuthStatus.SUCCESS, "请求成功", url=response.url), response

    def query_endpoint(
        self,
        url: str,
        *,
        method: str = "POST",
        data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        json: Any = None,
        **kwargs: Any,
    ) -> tuple[AuthResult, PageResult]:
        if not url:
            return AuthResult(AuthStatus.UNKNOWN_ERROR, "接口 URL 未配置"), None
        auth, response = self.request_protected(
            method,
            url,
            data=data,
            params=params,
            json=json,
            **kwargs,
        )
        if not response:
            return auth, None
        return auth, self._parse_response(response)

    def query_grades(
        self,
        academic_year: str,
        term: str,
        course_mark: str = "0",
        *,
        page_size: int = 15,
        current_page: int = 1,
        timestamp: int | None = None,
        **extra: Any,
    ) -> tuple[AuthResult, Any]:
        data = {
            "xnm": _academic_year_code(academic_year),
            "xqm": term,
            "sfzgcj": "",
            "kcbj": course_mark,
            "pkey": "",
            "_search": "false",
            "nd": timestamp or 0,
            "queryModel.showCount": page_size,
            "queryModel.currentPage": current_page,
            "queryModel.sortName": " ",
            "queryModel.sortOrder": "asc",
            "time": "2",
            **extra,
        }
        auth, data = self.query_endpoint(self.config.grade_url, data=data)
        if isinstance(data, dict):
            return auth, PageResult.from_dict(data, GradeRecord)
        return auth, PageResult(items=[])

    def query_timetable(
        self,
        academic_year: str,
        term: str,
        *,
        view_type: str = "ck",
        student_code: str = "",
        course_category: str = "",
        course_type: str = "",
        **extra: Any,
    ) -> tuple[AuthResult, TimetableResult]:
        data = {
            "xnm": _academic_year_code(academic_year),
            "xqm": term,
            "kzlx": view_type,
            "xsdm": student_code,
            "kclbdm": course_category,
            "kclxdm": course_type,
            **extra,
        }
        auth, data = self.query_endpoint(self.config.timetable_url, data=data)
        if isinstance(data, dict):
            return auth, TimetableResult.from_dict(data)
        return auth, TimetableResult()

    def query_mobile_timetable(
        self,
        academic_year: str,
        term: str,
        campus_id: str = "1",
        **extra: Any,
    ) -> tuple[AuthResult, TimetableResult]:
        data = {
            "xnm": _academic_year_code(academic_year),
            "xqm": term,
            "xqh_id": campus_id,
            **extra,
        }
        auth, data = self.query_endpoint(self.config.mobile_timetable_url, data=data)
        if isinstance(data, dict):
            return auth, TimetableResult.from_dict(data)
        return auth, TimetableResult()

    def query_exam_schedule(
        self,
        academic_year: str,
        term: str,
        *,
        exam_name_id: str = "",
        course_code: str = "",
        course_name: str = "",
        exam_date: str = "",
        department_id: str = "",
        page_size: int = 15,
        current_page: int = 1,
        timestamp: int | None = None,
        **extra: Any,
    ) -> tuple[AuthResult, PageResult]:
        data = {
            "xnm": _academic_year_code(academic_year),
            "xqm": term,
            "ksmcdmb_id": exam_name_id,
            "kch": course_code,
            "kc": course_name,
            "ksrq": exam_date,
            "kkbm_id": department_id,
            "_search": "false",
            "nd": timestamp or 0,
            "queryModel.showCount": page_size,
            "queryModel.currentPage": current_page,
            "queryModel.sortName": " ",
            "queryModel.sortOrder": "asc",
            "time": "1",
            **extra,
        }
        auth, data = self.query_endpoint(self.config.exam_schedule_url, data=data)
        if isinstance(data, dict):
            return auth, PageResult.from_dict(data, ExamScheduleRecord)
        return auth, PageResult(items=[])

    def query_student_info(self, **params: Any) -> tuple[AuthResult, Any]:
        return self.query_endpoint(self.config.student_info_url, data=params)

    def query_training_plan(self, **params: Any) -> tuple[AuthResult, Any]:
        return self.query_endpoint(self.config.training_plan_url, data=params)

    def query_course_selection(self, **params: Any) -> tuple[AuthResult, Any]:
        return self.query_endpoint(self.config.course_selection_url, data=params)

    def query_empty_classrooms(self, **params: Any) -> tuple[AuthResult, Any]:
        return self.query_endpoint(self.config.empty_classroom_url, data=params)

    def _parse_response(self, response: requests.Response) -> Any:
        content_type = response.headers.get("content-type", "")
        if "json" in content_type.lower():
            return response.json()
        return response.text
