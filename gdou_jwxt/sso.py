from __future__ import annotations

import html as html_lib
import json
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlencode, urljoin, urlparse, urlunparse

import requests

from .config import JwxtConfig
from .crypto import encrypt_password
from .detector import (
    classify_login_response,
    extract_login_error,
    is_jwxt_authenticated_response,
    is_reauth_page_html,
    is_reauth_url,
    is_wfw_gateway_response,
    normalize_authserver_url,
    rewrite_url_for_mode,
)
from .models import AuthResult, AuthStatus, CaptchaChallenge, ChallengeType, MfaContext, MfaMethod, NetworkMode

CaptchaSolver = Callable[[bytes], str]


@dataclass(frozen=True)
class PwdLoginForm:
    action_url: str
    pwd_encrypt_salt: str
    execution: str
    lt: str = ""
    cllt: str = "userNameLogin"
    dllt: str = "generalLogin"
    event_id: str = "submit"


class _FormHTMLParser(HTMLParser):
    """提取页面中所有 <form> 及其内部的 <input> 属性。"""

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict[str, Any]] = []
        self._current_form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        lower_tag = tag.lower()
        attr_map = {k.lower(): (v or "") for k, v in attrs}
        if lower_tag == "form":
            self._current_form = {"attrs": attr_map, "inputs": []}
            self.forms.append(self._current_form)
        elif lower_tag == "input" and self._current_form is not None:
            self._current_form["inputs"].append(attr_map)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._current_form = None


def _ensure_service_query(action_url: str, service: str) -> str:
    if not service:
        return action_url
    parsed = urlparse(action_url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    if "service" in query and any(query["service"]):
        return action_url
    extra = urlencode({"service": service})
    new_query = f"{parsed.query}&{extra}" if parsed.query else extra
    return urlunparse(parsed._replace(query=new_query))


def parse_pwd_login_form(html: str, page_url: str, default_service: str = "") -> PwdLoginForm:
    parser = _FormHTMLParser()
    parser.feed(html or "")

    target_form: dict[str, Any] | None = None
    for form in parser.forms:
        if form["attrs"].get("id") == "pwdFromId":
            target_form = form
            break

    if target_form is None:
        for form in parser.forms:
            if any(inp.get("id") == "pwdEncryptSalt" for inp in form["inputs"]):
                target_form = form
                break

    if target_form is None:
        raise ValueError("登录页中未找到账号密码登录表单 (#pwdFromId)")

    by_name: dict[str, str] = {}
    by_id: dict[str, str] = {}
    for inp in target_form["inputs"]:
        name = inp.get("name", "")
        elem_id = inp.get("id", "")
        val = inp.get("value", "")
        if name and name not in by_name:
            by_name[name] = val
        if elem_id and elem_id not in by_id:
            by_id[elem_id] = val

    raw_action = target_form["attrs"].get("action") or "/authserver/login"
    action_url = urljoin(page_url, raw_action)

    page_query = parse_qs(urlparse(page_url).query)
    service = (page_query.get("service") or [default_service])[0]
    action_url = _ensure_service_query(action_url, service)

    return PwdLoginForm(
        action_url=action_url,
        pwd_encrypt_salt=by_id.get("pwdEncryptSalt") or by_name.get("pwdEncryptSalt", ""),
        execution=by_name.get("execution") or by_id.get("execution", ""),
        lt=by_name.get("lt", ""),
        cllt=by_name.get("cllt") or "userNameLogin",
        dllt=by_name.get("dllt") or "generalLogin",
        event_id=by_name.get("_eventId") or "submit",
    )


def _unescape_js_string(raw: str) -> str:
    """解码 Thymeleaf 内联 JS 字符串字面量中的转义字符（如 \\/、\\uXXXX）。"""
    if not raw:
        return ""
    try:
        escaped = raw.replace("\\'", "'").replace('"', '\\"')
        return str(json.loads(f'"{escaped}"')).strip()
    except (ValueError, TypeError):
        return html_lib.unescape(raw.replace(r"\/", "/")).strip()


def _extract_reauth_block(html: str) -> str:
    match = re.search(r"reAuthParams\s*=\s*\{(.*?)\}", html, re.DOTALL)
    return match.group(1) if match else ""


def _extract_js_param(html: str, key: str) -> str:
    direct_patterns = (
        rf"reAuthParams\.{re.escape(key)}\s*=\s*['\"]([^'\"]*)['\"]",
        rf"reAuthParams\[['\"]{re.escape(key)}['\"]\]\s*=\s*['\"]([^'\"]*)['\"]",
    )
    for pattern in direct_patterns:
        match = re.search(pattern, html)
        if match:
            return _unescape_js_string(match.group(1))

    block = _extract_reauth_block(html)
    if block:
        block_match = re.search(rf"['\"]?{re.escape(key)}['\"]?\s*:\s*['\"]([^'\"]*)['\"]", block)
        if block_match:
            return _unescape_js_string(block_match.group(1))

    fallback_patterns = (
        rf"['\"]?{re.escape(key)}['\"]?\s*:\s*['\"]([^'\"]*)['\"]",
        rf"<input[^>]*\b(?:id|name)=['\"]{re.escape(key)}['\"][^>]*\bvalue=['\"]([^'\"]*)['\"]",
        rf"<input[^>]*\bvalue=['\"]([^'\"]*)['\"][^>]*\b(?:id|name)=['\"]{re.escape(key)}['\"]",
    )
    for pattern in fallback_patterns:
        match = re.search(pattern, html)
        if match:
            return _unescape_js_string(match.group(1))
    return ""


def _normalize_service_url(value: str) -> str:
    cleaned = _unescape_js_string(value)
    if cleaned.lower().startswith(("http%3a", "https%3a")):
        cleaned = unquote(cleaned)
    return cleaned


def parse_reauth_page(
    html: str,
    page_url: str,
    username: str,
    default_service: str = "",
    *,
    network_mode: NetworkMode = NetworkMode.CAMPUS,
) -> MfaContext:
    page_query = parse_qs(urlparse(page_url).query)
    raw_service = _extract_js_param(html, "service") or (page_query.get("service") or [default_service])[0]
    service = _normalize_service_url(raw_service)
    if not service.startswith(("http://", "https://")) and page_query.get("service"):
        service = _normalize_service_url(page_query["service"][0])
    if not service.startswith(("http://", "https://")) and default_service:
        service = default_service

    is_multifactor = _extract_js_param(html, "isMultifactor") or (page_query.get("isMultifactor") or ["true"])[0]
    reauth_type = _extract_js_param(html, "reAuthType") or "4"
    reauth_user_id = _extract_js_param(html, "reAuthUserId") or username
    is_sleep_account = _extract_js_param(html, "isSleepAccount") or "0"

    available: list[MfaMethod] = []
    if reauth_type == "4" or re.search(r'id=["\']4["\']', html) or "企业微信" in html:
        available.append(MfaMethod.WECHAT)
    if reauth_type == "3" or re.search(r'id=["\']3["\']', html) or "手机动态码" in html or "短信验证码" in html:
        available.append(MfaMethod.SMS)

    return MfaContext(
        username=username,
        reauth_user_id=reauth_user_id,
        reauth_type=reauth_type,
        method=MfaMethod.from_reauth_type(reauth_type),
        service=service,
        is_multifactor=is_multifactor,
        is_sleep_account=is_sleep_account,
        network_mode=network_mode,
        available_methods=tuple(available),
    )


def _resolve_redirect_url(
    current_url: str,
    location: str,
    mode: NetworkMode,
    *,
    jwxt_base_url: str,
    authserver_base_url: str,
    wfw_base_url: str,
) -> str:
    joined = urljoin(current_url, location)
    rewritten = rewrite_url_for_mode(
        joined,
        mode,
        jwxt_base_url=jwxt_base_url,
        authserver_base_url=authserver_base_url,
        wfw_base_url=wfw_base_url,
    )
    # 若在校园网强制使用 external 模式，wfw 可能 302 弹回直连 jw.gdou.edu.cn；避免回环死循环
    if rewritten == current_url and joined != current_url:
        return normalize_authserver_url(joined, authserver_base_url)
    return rewritten


def request_following_https(
    session: requests.Session,
    method: str,
    url: str,
    *,
    authserver_base_url: str,
    timeout: float,
    mode: NetworkMode = NetworkMode.CAMPUS,
    jwxt_base_url: str = "https://jw.gdou.edu.cn",
    wfw_base_url: str = "https://wfw.gdou.edu.cn",
    data: Any = None,
    params: Any = None,
    headers: dict[str, str] | None = None,
    max_redirects: int = 15,
) -> requests.Response:
    """受控重定向请求：按网络模式规范化 HTTPS 与 wfw 反代地址，避免 Cookie 丢失。"""
    current_method = method.upper()
    effective_mode = mode
    current_url = rewrite_url_for_mode(
        url,
        effective_mode,
        jwxt_base_url=jwxt_base_url,
        authserver_base_url=authserver_base_url,
        wfw_base_url=wfw_base_url,
    )
    current_data = data
    current_params = params
    history: list[requests.Response] = []
    wfw_host = (urlparse(wfw_base_url).hostname or "wfw.gdou.edu.cn").lower()
    jwxt_host = (urlparse(jwxt_base_url).hostname or "jw.gdou.edu.cn").lower()

    for _ in range(max_redirects + 1):
        response = session.request(
            current_method,
            current_url,
            data=current_data,
            params=current_params,
            headers=headers,
            timeout=timeout,
            allow_redirects=False,
        )
        location = response.headers.get("Location")
        if response.status_code not in (301, 302, 303, 307, 308) or not location:
            response.history = history
            return response

        history.append(response)
        resp_url = response.url or current_url
        # 若 wfw 识别到当前为校内 IP 并主动 302 弹回直连 jw.gdou.edu.cn，本次重定向链不再反复套回 wfw
        if (
            effective_mode == NetworkMode.EXTERNAL
            and (urlparse(resp_url).hostname or "").lower() == wfw_host
            and (urlparse(urljoin(resp_url, location)).hostname or "").lower() == jwxt_host
        ):
            effective_mode = NetworkMode.CAMPUS

        current_url = _resolve_redirect_url(
            resp_url,
            location,
            effective_mode,
            jwxt_base_url=jwxt_base_url,
            authserver_base_url=authserver_base_url,
            wfw_base_url=wfw_base_url,
        )
        current_params = None

        if response.status_code in (301, 302, 303) and current_method == "POST":
            current_method = "GET"
            current_data = None

    raise requests.TooManyRedirects(f"重定向次数超过限制 ({max_redirects})")


def detect_network_mode(session: requests.Session, config: JwxtConfig) -> NetworkMode:
    """通过应用网关 netcheck 探测当前应走校内直连还是校外 wfw 代理。"""
    wfw_host = (urlparse(config.wfw_base_url).hostname or "wfw.gdou.edu.cn").lower()
    jwxt_host = (urlparse(config.jwxt_base_url).hostname or "jw.gdou.edu.cn").lower()
    try:
        resp = session.get(
            config.netcheck_url,
            timeout=min(config.timeout, 8.0),
            allow_redirects=False,
        )
        location = (resp.headers.get("Location") or "").lower()
        if wfw_host in location:
            return NetworkMode.EXTERNAL
        if jwxt_host in location:
            return NetworkMode.CAMPUS
    except requests.RequestException:
        pass
    # wfw 在校内和校外均可访问，探测异常时保守选择 EXTERNAL
    return NetworkMode.EXTERNAL


class SsoClient:
    """纯 HTTP 金智统一身份认证客户端。"""

    def __init__(self, config: JwxtConfig | None = None) -> None:
        self.config = config or JwxtConfig()

    @property
    def _authserver_host(self) -> str:
        return (urlparse(self.config.authserver_base_url).hostname or "authserver.gdou.edu.cn").lower()

    @property
    def _jwxt_host(self) -> str:
        return (urlparse(self.config.jwxt_base_url).hostname or "jw.gdou.edu.cn").lower()

    @property
    def _wfw_host(self) -> str:
        return (urlparse(self.config.wfw_base_url).hostname or "wfw.gdou.edu.cn").lower()

    def resolve_network_mode(
        self,
        session: requests.Session,
        network_mode: NetworkMode | str | None = None,
    ) -> NetworkMode:
        requested = NetworkMode.parse(network_mode, default=self.config.network_mode)
        if requested == NetworkMode.AUTO:
            return detect_network_mode(session, self.config)
        return requested

    def _endpoint(self, path: str, mode: NetworkMode = NetworkMode.CAMPUS) -> str:
        return f"{self.config.authserver_base_for(mode).rstrip('/')}/{path.lstrip('/')}"

    def begin_login(
        self,
        session: requests.Session,
        username: str,
        password: str,
        *,
        network_mode: NetworkMode | str | None = None,
        captcha_code: str | None = None,
        captcha_solver: CaptchaSolver | None = None,
    ) -> AuthResult:
        mode = self.resolve_network_mode(session, network_mode)
        if mode == NetworkMode.EXTERNAL:
            # 清理残留的未激活/过期 wfw Cookie，确保 CAS 跳回 wfw/?ticket=... 时签发全新的已激活 WFWSESSID
            self._clear_wfw_cookies(session)

        service_url = self.config.service_url_for(mode)
        login_url = self.config.authserver_login_url_for(mode)

        try:
            login_page = request_following_https(
                session,
                "GET",
                login_url,
                authserver_base_url=self.config.authserver_base_url,
                jwxt_base_url=self.config.jwxt_base_url,
                wfw_base_url=self.config.wfw_base_url,
                mode=mode,
                timeout=self.config.timeout,
            )
        except requests.RequestException as exc:
            return AuthResult(AuthStatus.NETWORK_ERROR, str(exc))

        if self._is_sso_landing(login_page, mode):
            landed, land_err = self._complete_external_jwxt_sso(session, login_page, mode)
            if land_err is not None:
                return land_err
            if landed is not None:
                return AuthResult(
                    AuthStatus.SUCCESS,
                    "已通过统一身份认证静默登录",
                    url=landed.url,
                    metadata={"source": "sso_silent", "network_mode": self._mode_from_url(landed.url, mode).value},
                )

        if is_reauth_url(login_page.url) or is_reauth_page_html(login_page.text):
            ctx = parse_reauth_page(
                login_page.text,
                login_page.url,
                username,
                service_url,
                network_mode=mode,
            )
            ctx._session = session
            return AuthResult(
                AuthStatus.NEED_MANUAL_VERIFICATION,
                "统一身份认证平台要求二次验证",
                ChallengeType.MFA_REQUIRED,
                url=login_page.url,
                data=ctx,
                metadata={"network_mode": mode.value},
            )

        try:
            form = parse_pwd_login_form(login_page.text, login_page.url, service_url)
        except ValueError as exc:
            return AuthResult(AuthStatus.UNKNOWN_ERROR, str(exc), url=login_page.url)

        self._ensure_browser_fingerprint(session, mode)

        resolved_captcha = (captcha_code or "").strip()
        if not resolved_captcha:
            need_captcha_result = self._check_and_handle_captcha(
                session,
                username,
                mode=mode,
                captcha_solver=captcha_solver,
                page_url=login_page.url,
            )
            if isinstance(need_captcha_result, AuthResult):
                return need_captcha_result
            resolved_captcha = need_captcha_result

        try:
            encrypted_password = encrypt_password(password, form.pwd_encrypt_salt)
        except ValueError as exc:
            return AuthResult(AuthStatus.UNKNOWN_ERROR, f"密码加密失败: {exc}", url=login_page.url)

        payload = {
            "username": username,
            "password": encrypted_password,
            "captcha": resolved_captcha,
            "_eventId": form.event_id,
            "cllt": form.cllt,
            "dllt": form.dllt,
            "lt": form.lt,
            "execution": form.execution,
        }

        try:
            response = request_following_https(
                session,
                "POST",
                form.action_url,
                authserver_base_url=self.config.authserver_base_url,
                jwxt_base_url=self.config.jwxt_base_url,
                wfw_base_url=self.config.wfw_base_url,
                mode=mode,
                timeout=self.config.timeout,
                data=payload,
                headers={"Referer": login_page.url},
            )
        except requests.RequestException as exc:
            return AuthResult(AuthStatus.NETWORK_ERROR, str(exc))

        if self._is_sso_landing(response, mode):
            landed, land_err = self._complete_external_jwxt_sso(session, response, mode)
            if land_err is not None:
                return land_err
            if landed is not None:
                return AuthResult(
                    AuthStatus.SUCCESS,
                    "已获得教务系统登录态",
                    url=landed.url,
                    metadata={"source": "sso", "network_mode": self._mode_from_url(landed.url, mode).value},
                )

        if is_reauth_url(response.url) or is_reauth_page_html(response.text):
            ctx = parse_reauth_page(
                response.text,
                response.url,
                username,
                service_url,
                network_mode=mode,
            )
            ctx._session = session
            return AuthResult(
                AuthStatus.NEED_MANUAL_VERIFICATION,
                "统一身份认证平台要求二次验证",
                ChallengeType.MFA_REQUIRED,
                url=response.url,
                data=ctx,
                metadata={"network_mode": mode.value},
            )

        result = classify_login_response(
            response.text,
            response.url,
            jwxt_host=self._jwxt_host,
            authserver_host=self._authserver_host,
            wfw_host=self._wfw_host,
        )
        result.metadata["network_mode"] = mode.value
        if result.challenge_type == ChallengeType.IMAGE_CAPTCHA:
            challenge = self._fetch_captcha_challenge(session, username, result.message, mode=mode)
            if challenge is not None:
                result.data = challenge
        return result

    def switch_mfa_method(self, context: MfaContext, method: MfaMethod) -> AuthResult:
        validation_err = self._validate_context(context)
        if validation_err is not None:
            return validation_err

        if method == MfaMethod.AUTO:
            if context.reauth_type in ("3", "4"):
                context.method = MfaMethod.from_reauth_type(context.reauth_type)
                return AuthResult(AuthStatus.SUCCESS, f"使用默认方式: {context.method.label}")
            for candidate in (MfaMethod.WECHAT, MfaMethod.SMS):
                res = self.switch_mfa_method(context, candidate)
                if res.ok:
                    return res
            return AuthResult(AuthStatus.VERIFICATION_INCOMPLETE, "当前账号无可用的企业微信或短信二次验证方式")

        target_type = method.reauth_type
        if context.reauth_type == target_type:
            context.method = method
            return AuthResult(AuthStatus.SUCCESS, f"当前已处于{method.label}")

        assert context._session is not None
        try:
            response = context._session.post(
                self._endpoint("reAuthCheck/changeReAuthType.do", context.network_mode),
                data={
                    "isMultifactor": context.is_multifactor,
                    "reAuthType": target_type,
                    "service": context.service,
                },
                timeout=self.config.timeout,
            )
            body = response.json()
        except requests.RequestException as exc:
            return AuthResult(AuthStatus.NETWORK_ERROR, str(exc))
        except ValueError:
            return AuthResult(AuthStatus.UNKNOWN_ERROR, "切换二次验证方式接口返回了非 JSON 内容")

        if str(body.get("code") or "") == "1":
            data = body.get("data") or {}
            new_type = str(data.get("reAuthType") or target_type)
            context.reauth_type = new_type
            context.method = MfaMethod.from_reauth_type(new_type)
            return AuthResult(AuthStatus.SUCCESS, f"已切换到{context.method.label}")

        return AuthResult(
            AuthStatus.VERIFICATION_INCOMPLETE,
            str(body.get("message") or body.get("msg") or f"切换到{method.label}失败"),
            metadata={"switch_code": body.get("code"), "switch_body": body},
        )

    def send_mfa_code(
        self,
        context: MfaContext,
        *,
        method: MfaMethod | None = None,
    ) -> AuthResult:
        validation_err = self._validate_context(context)
        if validation_err is not None:
            return validation_err

        target_method = method or self.config.mfa_method
        switch_res = self.switch_mfa_method(context, target_method)
        if not switch_res.ok:
            return switch_res

        active_method = MfaMethod.from_reauth_type(context.reauth_type)
        auth_code_type_name = active_method.auth_code_type_name
        if not auth_code_type_name:
            return AuthResult(
                AuthStatus.VERIFICATION_INCOMPLETE,
                f"不支持的二次验证方式编码: {context.reauth_type}",
            )

        assert context._session is not None
        try:
            response = context._session.post(
                self._endpoint("dynamicCode/getDynamicCodeByReauth.do", context.network_mode),
                data={
                    "userName": context.reauth_user_id,
                    "authCodeTypeName": auth_code_type_name,
                },
                timeout=self.config.timeout,
            )
            body = response.json()
        except requests.RequestException as exc:
            return AuthResult(AuthStatus.NETWORK_ERROR, str(exc))
        except ValueError:
            return AuthResult(AuthStatus.UNKNOWN_ERROR, "发送二次验证码接口返回了非 JSON 内容")

        res_code = str(body.get("res") or "")
        message = str(body.get("returnMessage") or "")
        mobile = body.get("mobile")
        if mobile:
            message = f"{message}{mobile}"

        if res_code == "success":
            countdown = _safe_int(body.get("codeTime"), default=120)
            context.code_sent = True
            context.countdown = countdown
            context.message = message or "短信验证码已发送"
            return AuthResult(AuthStatus.SUCCESS, context.message, data=context)

        if res_code == "wechat_success":
            countdown = _safe_int(body.get("codeTime"), default=120)
            context.code_sent = True
            context.countdown = countdown
            context.message = message or "企业微信验证码已发送"
            return AuthResult(AuthStatus.SUCCESS, context.message, data=context)

        if res_code == "code_time_fail":
            context.countdown = _safe_int(body.get("codeTime"), default=0)
            return AuthResult(
                AuthStatus.VERIFICATION_INCOMPLETE,
                message or "验证码发送过于频繁，请稍后再试",
                data=context,
            )

        return AuthResult(
            AuthStatus.VERIFICATION_INCOMPLETE,
            message or f"发送{active_method.label}失败",
            data=context,
        )

    def verify_mfa_code(
        self,
        context: MfaContext,
        code: str,
        *,
        trust_device: bool | None = None,
    ) -> AuthResult:
        validation_err = self._validate_context(context)
        if validation_err is not None:
            return validation_err

        clean_code = (code or "").strip()
        if not clean_code:
            return AuthResult(AuthStatus.VERIFICATION_INCOMPLETE, "二次验证码不能为空", data=context)

        use_trust = self.config.trust_device if trust_device is None else trust_device
        payload = {
            "service": context.service,
            "reAuthType": context.reauth_type,
            "isMultifactor": context.is_multifactor,
            "password": "",
            "dynamicCode": clean_code,
            "uuid": "",
            "answer1": "",
            "answer2": "",
            "otpCode": "",
            "skipTmpReAuth": "true" if use_trust else "false",
        }

        assert context._session is not None
        mode = context.network_mode
        try:
            submit_resp = context._session.post(
                self._endpoint("reAuthCheck/reAuthSubmit.do", mode),
                data=payload,
                timeout=self.config.timeout,
            )
            body = submit_resp.json()
        except requests.RequestException as exc:
            return AuthResult(AuthStatus.NETWORK_ERROR, str(exc))
        except ValueError:
            return AuthResult(AuthStatus.UNKNOWN_ERROR, "提交二次验证接口返回了非 JSON 内容")

        code_val = str(body.get("code") or "")
        if code_val in ("reAuth_failed", "reAuth_unauthorized"):
            return AuthResult(
                AuthStatus.VERIFICATION_INCOMPLETE,
                str(body.get("msg") or "二次验证码校验失败"),
                ChallengeType.MFA_REQUIRED,
                data=context,
            )

        # 与 reAuth.js 保持一致：验证成功后跳回 /authserver/login?service=... 签发 ST 票据
        if mode == NetworkMode.EXTERNAL:
            self._clear_wfw_cookies(context._session)
        next_url = self._endpoint("login", mode)
        if context.service:
            next_url = f"{next_url}?service={quote(context.service, safe='')}"

        try:
            final_resp = request_following_https(
                context._session,
                "GET",
                next_url,
                authserver_base_url=self.config.authserver_base_url,
                jwxt_base_url=self.config.jwxt_base_url,
                wfw_base_url=self.config.wfw_base_url,
                mode=mode,
                timeout=self.config.timeout,
            )
        except requests.RequestException as exc:
            return AuthResult(AuthStatus.NETWORK_ERROR, str(exc))

        if self._is_sso_landing(final_resp, mode):
            landed, land_err = self._complete_external_jwxt_sso(context._session, final_resp, mode)
            if land_err is not None:
                return land_err
            if landed is not None:
                context.consumed = True
                return AuthResult(
                    AuthStatus.SUCCESS,
                    "二次验证通过，已获得教务系统登录态",
                    url=landed.url,
                    metadata={
                        "source": "sso_mfa",
                        "trusted": use_trust,
                        "network_mode": self._mode_from_url(landed.url, mode).value,
                    },
                )

        error_msg = extract_login_error(final_resp.text)
        title_match = re.search(r"<title[^>]*>(.*?)</title>", final_resp.text or "", re.IGNORECASE | re.DOTALL)
        return AuthResult(
            AuthStatus.VERIFICATION_INCOMPLETE,
            error_msg or "二次验证后未能完成教务系统跳转",
            url=final_resp.url,
            metadata={
                "submit_code": code_val,
                "submit_msg": str(body.get("msg") or ""),
                "final_status": final_resp.status_code,
                "final_url": final_resp.url,
                "final_title": title_match.group(1).strip() if title_match else "",
                "history": [(h.status_code, h.url) for h in final_resp.history],
            },
        )

    def _check_and_handle_captcha(
        self,
        session: requests.Session,
        username: str,
        *,
        mode: NetworkMode,
        captcha_solver: CaptchaSolver | None,
        page_url: str,
    ) -> str | AuthResult:
        try:
            check_resp = session.get(
                self._endpoint("checkNeedCaptcha.htl", mode),
                params={"username": username},
                timeout=self.config.timeout,
            )
            raw_need = check_resp.json().get("isNeed")
            need_captcha = raw_need is True or str(raw_need).lower() == "true"
        except (requests.RequestException, ValueError):
            need_captcha = False

        if not need_captcha:
            return ""

        challenge = self._fetch_captcha_challenge(session, username, "页面要求输入图形验证码", mode=mode)
        if challenge is None:
            return AuthResult(AuthStatus.NETWORK_ERROR, "获取图形验证码图片失败", url=page_url)

        if captcha_solver is not None:
            code = (captcha_solver(challenge.image_bytes) or "").strip()
            if not code:
                return AuthResult(
                    AuthStatus.VERIFICATION_INCOMPLETE,
                    "未输入图形验证码",
                    ChallengeType.IMAGE_CAPTCHA,
                    url=page_url,
                    data=challenge,
                )
            return code

        return AuthResult(
            AuthStatus.NEED_MANUAL_VERIFICATION,
            challenge.message,
            ChallengeType.IMAGE_CAPTCHA,
            url=page_url,
            data=challenge,
            metadata={"network_mode": mode.value},
        )

    def _fetch_captcha_challenge(
        self,
        session: requests.Session,
        username: str,
        message: str,
        *,
        mode: NetworkMode,
    ) -> CaptchaChallenge | None:
        try:
            resp = session.get(self._endpoint("getCaptcha.htl", mode), timeout=self.config.timeout)
            if resp.status_code != 200 or not resp.content:
                return None
            return CaptchaChallenge(
                image_bytes=resp.content,
                content_type=resp.headers.get("Content-Type", "image/jpeg"),
                username=username,
                message=message,
            )
        except requests.RequestException:
            return None

    def _clear_wfw_cookies(self, session: requests.Session) -> None:
        """清理残留的 wfw 域名 Cookie，避免未激活 WFWSESSID 阻碍新票据激活。"""
        to_remove: list[tuple[str, str, str]] = []
        for cookie in session.cookies:
            domain = (cookie.domain or "").lstrip(".").lower()
            if domain == self._wfw_host:
                to_remove.append((cookie.domain, cookie.path, cookie.name))
        for domain, path, name in to_remove:
            try:
                session.cookies.clear(domain, path, name)
            except KeyError:
                pass

    def _is_sso_landing(self, response: requests.Response, mode: NetworkMode) -> bool:
        if is_jwxt_authenticated_response(
            response,
            jwxt_host=self._jwxt_host,
            authserver_host=self._authserver_host,
            wfw_host=self._wfw_host,
        ):
            return True
        if mode == NetworkMode.EXTERNAL and is_wfw_gateway_response(
            response,
            wfw_host=self._wfw_host,
            authserver_host=self._authserver_host,
        ):
            return True
        return False

    def _mode_from_url(self, url: str | None, fallback: NetworkMode) -> NetworkMode:
        host = (urlparse(url or "").hostname or "").lower()
        if host == self._jwxt_host:
            return NetworkMode.CAMPUS
        if host == self._wfw_host:
            return NetworkMode.EXTERNAL
        return fallback

    def _complete_external_jwxt_sso(
        self,
        session: requests.Session,
        response: requests.Response,
        mode: NetworkMode,
    ) -> tuple[requests.Response | None, AuthResult | None]:
        """校外模式在激活 WFWSESSID 后，通过 wfw/https://jw.gdou.edu.cn 建立教务系统会话。"""
        if mode != NetworkMode.EXTERNAL:
            return response, None

        landed_host = (urlparse(response.url or "").hostname or "").lower()
        if landed_host == self._jwxt_host and is_jwxt_authenticated_response(
            response,
            jwxt_host=self._jwxt_host,
            authserver_host=self._authserver_host,
            wfw_host=self._wfw_host,
        ):
            return response, None

        try:
            jw_entry = request_following_https(
                session,
                "GET",
                self.config.wfw_jwxt_init_url,
                authserver_base_url=self.config.authserver_base_url,
                jwxt_base_url=self.config.jwxt_base_url,
                wfw_base_url=self.config.wfw_base_url,
                mode=mode,
                timeout=self.config.timeout,
            )
        except requests.RequestException as exc:
            return None, AuthResult(AuthStatus.NETWORK_ERROR, str(exc))

        entry_host = (urlparse(jw_entry.url or "").hostname or "").lower()
        # 校园网环境强制走 external 时，wfw 可能 302 弹回直连 jw.gdou.edu.cn，利用已有 CASTGC 直连换票
        if entry_host == self._jwxt_host:
            if is_jwxt_authenticated_response(
                jw_entry,
                jwxt_host=self._jwxt_host,
                authserver_host=self._authserver_host,
                wfw_host=self._wfw_host,
            ):
                return jw_entry, None
            try:
                campus_resp = request_following_https(
                    session,
                    "GET",
                    self.config.authserver_login_url_for(NetworkMode.CAMPUS),
                    authserver_base_url=self.config.authserver_base_url,
                    jwxt_base_url=self.config.jwxt_base_url,
                    wfw_base_url=self.config.wfw_base_url,
                    mode=NetworkMode.CAMPUS,
                    timeout=self.config.timeout,
                )
            except requests.RequestException as exc:
                return None, AuthResult(AuthStatus.NETWORK_ERROR, str(exc))
            if is_jwxt_authenticated_response(
                campus_resp,
                jwxt_host=self._jwxt_host,
                authserver_host=self._authserver_host,
                wfw_host=self._wfw_host,
            ):
                return campus_resp, None
            return None, AuthResult(
                AuthStatus.VERIFICATION_INCOMPLETE,
                "校外网关跳转至直连教务系统后未能完成换票",
                url=campus_resp.url,
                metadata={"stage": "wfw_fallback_campus", "final_status": campus_resp.status_code},
            )

        if is_wfw_gateway_response(
            jw_entry,
            wfw_host=self._wfw_host,
            authserver_host=self._authserver_host,
        ):
            try:
                forward_resp = request_following_https(
                    session,
                    "GET",
                    self.config.wfw_jwxt_forward_url,
                    authserver_base_url=self.config.authserver_base_url,
                    jwxt_base_url=self.config.jwxt_base_url,
                    wfw_base_url=self.config.wfw_base_url,
                    mode=mode,
                    timeout=self.config.timeout,
                )
            except requests.RequestException as exc:
                return None, AuthResult(AuthStatus.NETWORK_ERROR, str(exc))
            if is_jwxt_authenticated_response(
                forward_resp,
                jwxt_host=self._jwxt_host,
                authserver_host=self._authserver_host,
                wfw_host=self._wfw_host,
            ):
                return forward_resp, None
            return None, AuthResult(
                AuthStatus.VERIFICATION_INCOMPLETE,
                "已进入校外网关教务入口，但初始化教务主页失败",
                url=forward_resp.url,
                metadata={"stage": "wfw_jwxt_forward", "final_status": forward_resp.status_code},
            )

        return None, AuthResult(
            AuthStatus.VERIFICATION_INCOMPLETE,
            "已激活校外网关，但换取教务系统登录态失败",
            url=jw_entry.url,
            metadata={"stage": "wfw_to_jwxt", "final_status": jw_entry.status_code},
        )

    def _ensure_browser_fingerprint(self, session: requests.Session, mode: NetworkMode) -> None:
        """确保会话已注册 MULTIFACTOR_BROWSER_FINGERPRINT Cookie（金智多因素与可信设备依赖）。"""
        target_host = self._authserver_host
        for cookie in session.cookies:
            if cookie.name == "MULTIFACTOR_BROWSER_FINGERPRINT" and cookie.value:
                domain = (cookie.domain or "").lstrip(".").lower()
                if not domain or domain == target_host or target_host.endswith(f".{domain}"):
                    return

        bfp = (self.config.device_fingerprint or "").strip().upper()
        if not bfp:
            bfp = secrets.token_hex(16).upper()

        try:
            session.get(
                self._endpoint("bfp/info", mode),
                params={"bfp": bfp},
                timeout=self.config.timeout,
            )
        except requests.RequestException:
            pass

    def _validate_context(self, context: MfaContext) -> AuthResult | None:
        if context.consumed:
            return AuthResult(AuthStatus.VERIFICATION_INCOMPLETE, "该二次验证上下文已使用，请重新登录")
        if context._session is None:
            return AuthResult(AuthStatus.VERIFICATION_INCOMPLETE, "二次验证上下文缺少绑定的会话对象")
        return None


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
