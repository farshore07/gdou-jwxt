from __future__ import annotations

import requests

from .config import JwxtConfig
from .cookie_store import CookieStore
from .auto_login import AutoLogin
from .models import AuthResult, AuthStatus


class Authenticator:
    def __init__(
        self,
        config: JwxtConfig | None = None,
        session: requests.Session | None = None,
        page_factory: object | None = None,
        auto_login: AutoLogin | None = None,
        cookie_store: CookieStore | None = None,
    ) -> None:
        self.config = config or JwxtConfig()
        self.session = session or requests.Session()
        self.session.headers.update(self.config.headers)
        self.auto_login = auto_login or AutoLogin(self.config, page_factory=page_factory)
        self.cookie_store = cookie_store or CookieStore(self.config.cookie_file)

    def validate_session(self) -> AuthResult:
        try:
            response = self.session.get(self.config.jwxt_home_url, timeout=self.config.timeout)
            return self._classify_response(response)
        except requests.RequestException as exc:
            return AuthResult(AuthStatus.NETWORK_ERROR, str(exc))

    def login(self, username: str, password: str) -> AuthResult:
        current = self.validate_session()
        if current.ok:
            return current
        if self.cookie_store.load(self.session):
            stored = self.validate_session()
            if stored.ok:
                return AuthResult(
                    AuthStatus.SUCCESS,
                    "已使用 Cookie 快速登录",
                    url=stored.url,
                    metadata={"source": "cookie"},
                )
        result, browser_session = self.auto_login.login(username, password)
        if browser_session is not None:
            self._replace_session(browser_session)
            if result.ok:
                self.cookie_store.save(self.session)
        return result

    def _replace_session(self, source: requests.Session) -> None:
        self.session.cookies.clear()
        for cookie in source.cookies:
            self.session.cookies.set(
                cookie.name,
                cookie.value,
                domain=cookie.domain,
                path=cookie.path,
            )

    def _classify_response(self, response: requests.Response) -> AuthResult:
        if response.url and "login" in response.url.lower():
            return AuthResult(AuthStatus.AUTHENTICATION_REQUIRED, "当前未获得有效登录态", url=response.url)
        return AuthResult(AuthStatus.SUCCESS, "已获得教务系统登录态", url=response.url)
