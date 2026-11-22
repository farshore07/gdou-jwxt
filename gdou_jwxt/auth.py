from __future__ import annotations

from collections.abc import Callable
from urllib.parse import urlparse

import requests
from requests.cookies import create_cookie

from .config import JwxtConfig
from .cookie_store import CookieStore
from .detector import is_jwxt_authenticated_response
from .models import AuthResult, AuthStatus, ChallengeType, MfaContext, MfaMethod, NetworkMode
from .sso import CaptchaSolver, SsoClient, request_following_https

MfaCodeProvider = Callable[[MfaContext], str]
SessionFactory = Callable[[], requests.Session]


def _copy_cookies(target: requests.Session, source: requests.Session, *, clear_target: bool = False) -> None:
    if clear_target:
        target.cookies.clear()
    for cookie in source.cookies:
        cloned = create_cookie(
            name=cookie.name,
            value=cookie.value,
            domain=cookie.domain,
            path=cookie.path,
            secure=cookie.secure,
            expires=cookie.expires,
        )
        target.cookies.set_cookie(cloned)


class Authenticator:
    def __init__(
        self,
        config: JwxtConfig | None = None,
        session: requests.Session | None = None,
        sso_client: SsoClient | None = None,
        cookie_store: CookieStore | None = None,
        *,
        mfa_code_provider: MfaCodeProvider | None = None,
        captcha_solver: CaptchaSolver | None = None,
        session_factory: SessionFactory | None = None,
        network_mode: NetworkMode | str | None = None,
    ) -> None:
        self.config = config or JwxtConfig()
        self._session_factory: SessionFactory = session_factory or requests.Session
        self.session = session or self._session_factory()
        self.session.headers.update(self.config.headers)
        self.sso_client = sso_client or SsoClient(self.config)
        self.cookie_store = cookie_store or CookieStore(self.config.resolved_cookie_file)
        self.mfa_code_provider = mfa_code_provider
        self.captcha_solver = captcha_solver
        self.network_mode = NetworkMode.parse(network_mode, default=self.config.network_mode)
        self._active_mode: NetworkMode | None = (
            None if self.network_mode == NetworkMode.AUTO else self.network_mode
        )

    @property
    def _authserver_host(self) -> str:
        return (urlparse(self.config.authserver_base_url).hostname or "authserver.gdou.edu.cn").lower()

    @property
    def _jwxt_host(self) -> str:
        return (urlparse(self.config.jwxt_base_url).hostname or "jw.gdou.edu.cn").lower()

    @property
    def _wfw_host(self) -> str:
        return (urlparse(self.config.wfw_base_url).hostname or "wfw.gdou.edu.cn").lower()

    def resolve_network_mode(self, network_mode: NetworkMode | str | None = None) -> NetworkMode:
        if network_mode is not None:
            parsed = NetworkMode.parse(network_mode)
            self.network_mode = parsed
            if parsed == NetworkMode.AUTO:
                self._active_mode = self.sso_client.resolve_network_mode(self.session, NetworkMode.AUTO)
            else:
                self._active_mode = parsed
            return self._active_mode

        if self._active_mode is None:
            self._active_mode = self.sso_client.resolve_network_mode(self.session, self.network_mode)
        return self._active_mode

    def validate_session(self, *, network_mode: NetworkMode | str | None = None) -> AuthResult:
        mode = self.resolve_network_mode(network_mode)
        try:
            response = request_following_https(
                self.session,
                "GET",
                self.config.jwxt_home_url,
                authserver_base_url=self.config.authserver_base_url,
                jwxt_base_url=self.config.jwxt_base_url,
                wfw_base_url=self.config.wfw_base_url,
                mode=mode,
                timeout=self.config.timeout,
            )
        except requests.RequestException as exc:
            return AuthResult(AuthStatus.NETWORK_ERROR, str(exc))

        if is_jwxt_authenticated_response(
            response,
            jwxt_host=self._jwxt_host,
            authserver_host=self._authserver_host,
            wfw_host=self._wfw_host,
        ):
            self._sync_active_mode_from_url(response.url, mode)
            return AuthResult(
                AuthStatus.SUCCESS,
                "已获得教务系统登录态",
                url=response.url,
                metadata={"network_mode": self.resolve_network_mode().value},
            )

        return AuthResult(
            AuthStatus.AUTHENTICATION_REQUIRED,
            "当前未获得有效登录态",
            url=response.url,
            metadata={"network_mode": mode.value},
        )

    def login(
        self,
        username: str,
        password: str,
        *,
        network_mode: NetworkMode | str | None = None,
        mfa_method: MfaMethod | None = None,
        trust_device: bool | None = None,
        mfa_code_provider: MfaCodeProvider | None = None,
        captcha_code: str | None = None,
        captcha_solver: CaptchaSolver | None = None,
        force_refresh: bool = False,
        max_mfa_attempts: int = 2,
    ) -> AuthResult:
        mode = self.resolve_network_mode(network_mode)

        if not force_refresh and len(self.session.cookies) > 0:
            current = self.validate_session(network_mode=mode)
            if current.ok:
                return current

        if self.cookie_store.load(self.session) and not force_refresh:
            stored = self.validate_session(network_mode=mode)
            if stored.ok:
                self.cookie_store.save(self.session)
                return AuthResult(
                    AuthStatus.SUCCESS,
                    "已使用 Cookie 快速登录",
                    url=stored.url,
                    metadata={"source": "cookie", "network_mode": mode.value},
                )

        # 使用独立事务 Session 执行本次认证，避免中途失败污染已有会话或发生多用户串号
        tx_session = self._new_transaction_session()
        result = self.sso_client.begin_login(
            tx_session,
            username,
            password,
            network_mode=mode,
            captcha_code=captcha_code,
            captcha_solver=captcha_solver or self.captcha_solver,
        )

        if result.ok:
            self._sync_active_mode_from_url(result.url, mode)
            self._commit_session(tx_session)
            return result

        if (
            result.status == AuthStatus.NEED_MANUAL_VERIFICATION
            and result.challenge_type == ChallengeType.MFA_REQUIRED
            and isinstance(result.data, MfaContext)
        ):
            ctx = result.data
            ctx._owner_id = id(self)
            provider = mfa_code_provider or self.mfa_code_provider
            if provider is None:
                return result
            return self._complete_mfa_with_provider(
                ctx,
                provider,
                mfa_method=mfa_method,
                trust_device=trust_device,
                max_attempts=max(1, max_mfa_attempts),
            )

        return result

    def send_mfa_code(
        self,
        context: MfaContext,
        *,
        method: MfaMethod | None = None,
    ) -> AuthResult:
        owner_err = self._check_context_owner(context)
        if owner_err is not None:
            return owner_err
        return self.sso_client.send_mfa_code(context, method=method)

    def verify_mfa_code(
        self,
        context: MfaContext,
        code: str,
        *,
        trust_device: bool | None = None,
    ) -> AuthResult:
        owner_err = self._check_context_owner(context)
        if owner_err is not None:
            return owner_err

        result = self.sso_client.verify_mfa_code(context, code, trust_device=trust_device)
        if result.ok and context._session is not None:
            self._sync_active_mode_from_url(result.url, context.network_mode)
            self._commit_session(context._session)
        return result

    def _complete_mfa_with_provider(
        self,
        context: MfaContext,
        provider: MfaCodeProvider,
        *,
        mfa_method: MfaMethod | None,
        trust_device: bool | None,
        max_attempts: int,
    ) -> AuthResult:
        send_res = self.send_mfa_code(context, method=mfa_method)
        if not send_res.ok:
            return send_res

        last_result: AuthResult = AuthResult(AuthStatus.VERIFICATION_INCOMPLETE, "二次验证未完成", data=context)
        for _ in range(max_attempts):
            code = (provider(context) or "").strip()
            if not code:
                return AuthResult(
                    AuthStatus.VERIFICATION_INCOMPLETE,
                    "已取消输入二次验证码",
                    ChallengeType.MFA_REQUIRED,
                    data=context,
                )
            verify_res = self.verify_mfa_code(context, code, trust_device=trust_device)
            if (
                verify_res.ok
                or verify_res.status != AuthStatus.VERIFICATION_INCOMPLETE
                or verify_res.challenge_type != ChallengeType.MFA_REQUIRED
            ):
                return verify_res
            context.message = verify_res.message
            last_result = verify_res

        return last_result

    def _new_transaction_session(self) -> requests.Session:
        tx_session = self._session_factory()
        tx_session.headers.update(self.config.headers)
        _copy_cookies(tx_session, self.session, clear_target=True)
        return tx_session

    def _commit_session(self, source: requests.Session) -> None:
        _copy_cookies(self.session, source, clear_target=True)
        self.cookie_store.save(self.session)

    def _sync_active_mode_from_url(self, final_url: str | None, fallback: NetworkMode) -> None:
        host = (urlparse(final_url or "").hostname or "").lower()
        if host == self._jwxt_host:
            self._active_mode = NetworkMode.CAMPUS
        elif host == self._wfw_host:
            self._active_mode = NetworkMode.EXTERNAL
        else:
            self._active_mode = fallback

    def _check_context_owner(self, context: MfaContext) -> AuthResult | None:
        if context._owner_id is not None and context._owner_id != id(self):
            return AuthResult(
                AuthStatus.VERIFICATION_INCOMPLETE,
                "二次验证上下文不属于当前认证器实例，已拒绝以防会话串号",
            )
        return None
