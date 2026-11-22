from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import requests

from .auth import Authenticator, MfaCodeProvider
from .config import JwxtConfig
from .detector import is_auth_redirect, is_login_page_html, is_reauth_page_html, rewrite_url_for_mode
from .models import (
    AuthResult,
    AuthStatus,
    ExamScheduleRecord,
    GradeRecord,
    MfaContext,
    MfaMethod,
    NetworkMode,
    PageResult,
    TimetableResult,
)
from .sso import CaptchaSolver


def _academic_year_code(academic_year: str) -> str:
    return academic_year.split("-", 1)[0].strip()


def _has_upload_payload(kwargs: dict[str, Any]) -> bool:
    if kwargs.get("files"):
        return True
    headers = kwargs.get("headers")
    if isinstance(headers, dict):
        for key, value in headers.items():
            if str(key).lower() == "content-type" and "multipart/form-data" in str(value).lower():
                return True
    return False


class JwxtClient:
    def __init__(
        self,
        username: str | None = None,
        password: str | None = None,
        config: JwxtConfig | None = None,
        session: requests.Session | None = None,
        authenticator: Authenticator | None = None,
        *,
        mfa_code_provider: MfaCodeProvider | None = None,
        captcha_solver: CaptchaSolver | None = None,
        network_mode: NetworkMode | str | None = None,
    ) -> None:
        self.config = config or JwxtConfig()
        self.username = username
        self.password = password
        self.session = session or (authenticator.session if authenticator is not None else requests.Session())
        self.session.headers.update(self.config.headers)
        self.authenticator = authenticator or Authenticator(
            self.config,
            self.session,
            mfa_code_provider=mfa_code_provider,
            captcha_solver=captcha_solver,
            network_mode=network_mode,
        )
        if authenticator is not None and network_mode is not None:
            self.authenticator.resolve_network_mode(network_mode)

    @property
    def _authserver_host(self) -> str:
        return (urlparse(self.config.authserver_base_url).hostname or "authserver.gdou.edu.cn").lower()

    @property
    def _jwxt_host(self) -> str:
        return (urlparse(self.config.jwxt_base_url).hostname or "jw.gdou.edu.cn").lower()

    @property
    def _wfw_host(self) -> str:
        return (urlparse(self.config.wfw_base_url).hostname or "wfw.gdou.edu.cn").lower()

    def login(
        self,
        *,
        network_mode: NetworkMode | str | None = None,
        mfa_method: MfaMethod | None = None,
        trust_device: bool | None = None,
        mfa_code_provider: MfaCodeProvider | None = None,
        captcha_code: str | None = None,
        captcha_solver: CaptchaSolver | None = None,
        force_refresh: bool = False,
    ) -> AuthResult:
        if not self.username or not self.password:
            return AuthResult(AuthStatus.AUTHENTICATION_REQUIRED, "缺少账号或密码")
        return self.authenticator.login(
            self.username,
            self.password,
            network_mode=network_mode,
            mfa_method=mfa_method,
            trust_device=trust_device,
            mfa_code_provider=mfa_code_provider,
            captcha_code=captcha_code,
            captcha_solver=captcha_solver,
            force_refresh=force_refresh,
        )

    def ensure_authenticated(
        self,
        *,
        force_refresh: bool = False,
        network_mode: NetworkMode | str | None = None,
    ) -> AuthResult:
        if not force_refresh:
            result = self.authenticator.validate_session(network_mode=network_mode)
            if result.ok:
                return result
        if not self.username or not self.password:
            return AuthResult(AuthStatus.AUTHENTICATION_REQUIRED, "缺少账号或密码")
        return self.authenticator.login(
            self.username,
            self.password,
            network_mode=network_mode,
            force_refresh=force_refresh,
        )

    def send_mfa_code(
        self,
        context: MfaContext,
        *,
        method: MfaMethod | None = None,
    ) -> AuthResult:
        return self.authenticator.send_mfa_code(context, method=method)

    def verify_mfa_code(
        self,
        context: MfaContext,
        code: str,
        *,
        trust_device: bool | None = None,
    ) -> AuthResult:
        return self.authenticator.verify_mfa_code(context, code, trust_device=trust_device)

    def request_protected(
        self,
        method: str,
        url: str,
        *,
        retry_on_expired: bool | None = None,
        expect_json: bool = False,
        **kwargs: Any,
    ) -> tuple[AuthResult, requests.Response | None]:
        allow_retry = self._resolve_retry_policy(method, retry_on_expired, kwargs)
        mode = self.authenticator.resolve_network_mode()

        if not self._has_jwxt_cookie(mode):
            self.authenticator.cookie_store.load(self.session)
        if not self._has_jwxt_cookie(mode):
            auth = self.ensure_authenticated(network_mode=mode)
            if not auth.ok:
                return auth, None
            mode = self.authenticator.resolve_network_mode()

        target_url = rewrite_url_for_mode(
            url,
            mode,
            jwxt_base_url=self.config.jwxt_base_url,
            authserver_base_url=self.config.authserver_base_url,
            wfw_base_url=self.config.wfw_base_url,
        )
        response, net_err = self._send_request(method, target_url, kwargs)
        if net_err is not None:
            return net_err, None
        assert response is not None

        if not self._is_expired_response(response, expect_json=expect_json):
            return AuthResult(AuthStatus.SUCCESS, "请求成功", url=response.url), response

        if not allow_retry:
            return (
                AuthResult(
                    AuthStatus.SESSION_EXPIRED,
                    "会话已失效且当前请求未启用自动重试",
                    url=response.url,
                ),
                None,
            )

        auth = self.ensure_authenticated(force_refresh=True, network_mode=mode)
        if not auth.ok:
            return auth, None
        mode = self.authenticator.resolve_network_mode()
        retry_url = rewrite_url_for_mode(
            url,
            mode,
            jwxt_base_url=self.config.jwxt_base_url,
            authserver_base_url=self.config.authserver_base_url,
            wfw_base_url=self.config.wfw_base_url,
        )

        retry_response, retry_net_err = self._send_request(method, retry_url, kwargs)
        if retry_net_err is not None:
            return retry_net_err, None
        assert retry_response is not None

        if self._is_expired_response(retry_response, expect_json=expect_json):
            return (
                AuthResult(
                    AuthStatus.SESSION_EXPIRED,
                    "重新认证后请求仍被重定向到登录页",
                    url=retry_response.url,
                ),
                None,
            )

        return AuthResult(AuthStatus.SUCCESS, "请求成功", url=retry_response.url), retry_response

    def query_endpoint(
        self,
        url: str,
        *,
        method: str = "POST",
        data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        json: Any = None,
        retry_on_expired: bool | None = None,
        expect_json: bool = False,
        **kwargs: Any,
    ) -> tuple[AuthResult, Any]:
        if not url:
            return AuthResult(AuthStatus.UNKNOWN_ERROR, "接口 URL 未配置"), None
        auth, response = self.request_protected(
            method,
            url,
            retry_on_expired=retry_on_expired,
            expect_json=expect_json,
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
    ) -> tuple[AuthResult, PageResult[GradeRecord]]:
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
        auth, payload = self.query_endpoint(
            self.config.grade_url,
            data=data,
            retry_on_expired=True,
            expect_json=True,
        )
        if isinstance(payload, dict):
            return auth, PageResult.from_dict(payload, GradeRecord)
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
        auth, payload = self.query_endpoint(
            self.config.timetable_url,
            data=data,
            retry_on_expired=True,
            expect_json=True,
        )
        if isinstance(payload, dict):
            return auth, TimetableResult.from_dict(payload)
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
        auth, payload = self.query_endpoint(
            self.config.mobile_timetable_url,
            data=data,
            retry_on_expired=True,
            expect_json=True,
        )
        if isinstance(payload, dict):
            return auth, TimetableResult.from_dict(payload)
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
    ) -> tuple[AuthResult, PageResult[ExamScheduleRecord]]:
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
        auth, payload = self.query_endpoint(
            self.config.exam_schedule_url,
            data=data,
            retry_on_expired=True,
            expect_json=True,
        )
        if isinstance(payload, dict):
            return auth, PageResult.from_dict(payload, ExamScheduleRecord)
        return auth, PageResult(items=[])

    def query_student_info(self, **params: Any) -> tuple[AuthResult, Any]:
        return self.query_endpoint(self.config.student_info_url, data=params)

    def query_training_plan(self, **params: Any) -> tuple[AuthResult, Any]:
        return self.query_endpoint(self.config.training_plan_url, data=params)

    def query_course_selection(self, **params: Any) -> tuple[AuthResult, Any]:
        return self.query_endpoint(self.config.course_selection_url, data=params)

    def query_empty_classrooms(self, **params: Any) -> tuple[AuthResult, Any]:
        return self.query_endpoint(self.config.empty_classroom_url, data=params)

    def _resolve_retry_policy(
        self,
        method: str,
        retry_on_expired: bool | None,
        kwargs: dict[str, Any],
    ) -> bool:
        if _has_upload_payload(kwargs):
            return False
        if retry_on_expired is not None:
            return retry_on_expired
        return method.upper() == "GET"

    def _has_jwxt_cookie(self, mode: NetworkMode) -> bool:
        targets = (self._wfw_host, self._jwxt_host) if mode == NetworkMode.EXTERNAL else (self._jwxt_host,)
        for cookie in self.session.cookies:
            domain = (cookie.domain or "").lstrip(".").lower()
            if not domain or any(domain == t or t.endswith(f".{domain}") for t in targets):
                return True
        return False

    def _send_request(
        self,
        method: str,
        url: str,
        kwargs: dict[str, Any],
    ) -> tuple[requests.Response | None, AuthResult | None]:
        try:
            response = self.session.request(
                method,
                url,
                timeout=self.config.timeout,
                **kwargs,
            )
            return response, None
        except requests.RequestException as exc:
            return None, AuthResult(AuthStatus.NETWORK_ERROR, str(exc))

    def _is_expired_response(self, response: requests.Response, *, expect_json: bool) -> bool:
        if is_auth_redirect(response, authserver_host=self._authserver_host):
            return True
        content_type = response.headers.get("content-type", "").lower()
        if "json" not in content_type and (
            is_login_page_html(response.text) or is_reauth_page_html(response.text)
        ):
            return True
        if expect_json and "json" not in content_type and response.status_code == 200:
            # 某些网关在未登录时可能返回非 JSON 提示页
            if "authserver" in response.text or "统一身份认证" in response.text:
                return True
        return False

    def _parse_response(self, response: requests.Response) -> Any:
        content_type = response.headers.get("content-type", "")
        if "json" in content_type.lower():
            try:
                return response.json()
            except ValueError:
                return response.text
        return response.text
