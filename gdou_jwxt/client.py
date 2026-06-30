from __future__ import annotations

from typing import Any

import requests

from .auth import Authenticator
from .config import JwxtConfig
from .models import AuthResult, AuthStatus


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

    def query_grades(self, **params: Any) -> tuple[AuthResult, Any]:
        auth, response = self.request_protected("POST", self.config.grade_url, data=params)
        if not response:
            return auth, None
        return auth, self._parse_response(response)

    def query_timetable(self, **params: Any) -> tuple[AuthResult, Any]:
        auth, response = self.request_protected("POST", self.config.timetable_url, data=params)
        if not response:
            return auth, None
        return auth, self._parse_response(response)

    def _parse_response(self, response: requests.Response) -> Any:
        content_type = response.headers.get("content-type", "")
        if "json" in content_type.lower():
            return response.json()
        return response.text
