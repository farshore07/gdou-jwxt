from __future__ import annotations

import html as html_lib
import re
from urllib.parse import urljoin, urlparse, urlunparse

import requests

from .models import AuthResult, AuthStatus, ChallengeType, NetworkMode

_AUTH_PATH_MARKERS = (
    "/xtgl/login_slogin.html",
    "/sso/jziotlogin",
    "/authserver/login",
    "/authserver/reauthcheck/",
)

_REAUTH_PATH_MARKERS = (
    "/reauthcheck/reauthloginview.do",
    "/reauthcheck/",
)

_INVALID_CREDENTIAL_MARKERS = (
    "用户名或密码",
    "用户名或者密码",
    "密码有误",
    "密码错误",
    "账号或密码",
    "帐号或密码",
    "账号不存在",
    "帐号不存在",
    "账户被锁定",
    "账号已锁定",
    "invalid password",
    "bad credentials",
)

_CAPTCHA_ERROR_MARKERS = (
    "验证码错误",
    "无效的验证码",
    "请输入验证码",
    "验证码已过期",
)

_ERROR_ELEMENT_PATTERNS = (
    re.compile(
        r'<span[^>]*\bid=["\']showErrorTip["\'][^>]*>(.*?)</span>',
        re.IGNORECASE | re.DOTALL,
    ),
    re.compile(
        r'<div[^>]*\bid=["\']msg["\'][^>]*>(.*?)</div>',
        re.IGNORECASE | re.DOTALL,
    ),
    re.compile(
        r'<span[^>]*\bclass=["\'][^"\']*form-error[^"\']*["\'][^>]*>(.*?)</span>',
        re.IGNORECASE | re.DOTALL,
    ),
)
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_LOGIN_FORM_ACTION_RE = re.compile(r'<form[^>]*\baction=["\'][^"\']*login_slogin', re.IGNORECASE)


def normalize_authserver_url(
    url: str,
    authserver_base_url: str = "https://authserver.gdou.edu.cn/authserver",
) -> str:
    """将 authserver 的 HTTP 跳转地址规范化为 HTTPS（与配置保持一致）。"""
    if not url:
        return url
    target = urlparse(url)
    base = urlparse(authserver_base_url)
    if (
        base.scheme == "https"
        and target.scheme == "http"
        and target.hostname
        and base.hostname
        and target.hostname.lower() == base.hostname.lower()
    ):
        return urlunparse(target._replace(scheme="https"))
    return url


def rewrite_url_for_mode(
    url: str,
    mode: NetworkMode,
    *,
    jwxt_base_url: str = "https://jw.gdou.edu.cn",
    authserver_base_url: str = "https://authserver.gdou.edu.cn/authserver",
    wfw_base_url: str = "https://wfw.gdou.edu.cn",
) -> str:
    """按校内直连 / 校外 wfw 网关模式规范化目标 URL。

    校外模式下：
    - authserver.gdou.edu.cn 保持直连（公网可直接访问，且校内/校外共用可信设备指纹）；
    - 先以 service=https://wfw.gdou.edu.cn/ 激活全新 WFWSESSID，再访问 wfw/https://jw.gdou.edu.cn 进入教务系统；
    - 教务业务请求 jw.gdou.edu.cn/<path>?<query> -> https://wfw.gdou.edu.cn/<path>?<query>
      （wfw 根据服务端会话与 urlss="https://jw.gdou.edu.cn" 路由并转发给 jw.gdou.edu.cn）。
    """
    if not url:
        return url
    normalized = normalize_authserver_url(url, authserver_base_url)
    if mode != NetworkMode.EXTERNAL:
        return normalized

    wfw_parsed = urlparse(wfw_base_url.rstrip("/"))
    wfw_host = (wfw_parsed.hostname or "wfw.gdou.edu.cn").lower()
    jwxt_host = (urlparse(jwxt_base_url).hostname or "jw.gdou.edu.cn").lower()

    parsed = urlparse(normalized)
    host = (parsed.hostname or "").lower()

    if host == wfw_host:
        return urlunparse(parsed._replace(scheme=wfw_parsed.scheme or "https"))

    if host == jwxt_host:
        return urlunparse(
            parsed._replace(
                scheme=wfw_parsed.scheme or "https",
                netloc=wfw_parsed.netloc,
            )
        )

    return normalized


def is_reauth_url(url: str) -> bool:
    if not url:
        return False
    parsed = urlparse(url)
    path = parsed.path.lower()
    return any(marker in path for marker in _REAUTH_PATH_MARKERS)


def is_auth_url(url: str, authserver_host: str = "authserver.gdou.edu.cn") -> bool:
    if not url:
        return False
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path.lower()
    if host and host == authserver_host.lower():
        return True
    return any(marker in path for marker in _AUTH_PATH_MARKERS)


def is_auth_redirect(
    response: requests.Response,
    authserver_host: str = "authserver.gdou.edu.cn",
) -> bool:
    """结合 response.url、response.history 与 Location 头判断是否跳转至认证页。"""
    candidates: list[str] = []

    if response.url:
        candidates.append(response.url)

    location = response.headers.get("Location")
    if location:
        candidates.append(urljoin(response.url or "", location))

    for prev in getattr(response, "history", None) or ():
        if prev.url:
            candidates.append(prev.url)
        prev_loc = prev.headers.get("Location")
        if prev_loc:
            candidates.append(urljoin(prev.url or "", prev_loc))

    return any(is_auth_url(candidate, authserver_host=authserver_host) for candidate in candidates)


def extract_login_error(html: str) -> str:
    if not html:
        return ""
    for pattern in _ERROR_ELEMENT_PATTERNS:
        for match in pattern.finditer(html):
            raw_text = _HTML_TAG_RE.sub("", match.group(1))
            text = html_lib.unescape(raw_text).strip()
            if text:
                return text
    return ""


def is_login_page_html(html: str) -> bool:
    if not html:
        return False
    return (
        'id="pwdFromId"' in html
        or "id='pwdFromId'" in html
        or 'id="pwdEncryptSalt"' in html
        or "正在跳转到统一认证" in html
        or bool(_LOGIN_FORM_ACTION_RE.search(html))
    )


def is_reauth_page_html(html: str) -> bool:
    if not html:
        return False
    return (
        "reAuthParams" in html
        or "reAuthCheck/reAuthSubmit.do" in html
        or "reAuthLoginView" in html
    )


def is_wfw_gateway_response(
    response: requests.Response,
    wfw_host: str = "wfw.gdou.edu.cn",
    authserver_host: str = "authserver.gdou.edu.cn",
) -> bool:
    """判断是否已通过 CAS 票据验证并落地在 wfw 校外网关。"""
    if response.status_code != 200:
        return False
    final_url = response.url or ""
    host = (urlparse(final_url).hostname or "").lower()
    if host != wfw_host.lower():
        return False
    if is_auth_url(final_url, authserver_host=authserver_host):
        return False
    text = response.text or ""
    if not text.strip():
        return False
    if is_login_page_html(text) or is_reauth_page_html(text):
        return False
    return True


def is_jwxt_authenticated_response(
    response: requests.Response,
    jwxt_host: str = "jw.gdou.edu.cn",
    authserver_host: str = "authserver.gdou.edu.cn",
    wfw_host: str = "wfw.gdou.edu.cn",
) -> bool:
    """判断最终落地响应是否为已登录的教务系统页面（允许经由 SSO 或 wfw 网关重定向而来）。"""
    if response.status_code != 200:
        return False
    final_url = response.url or ""
    parsed = urlparse(final_url)
    host = (parsed.hostname or "").lower()
    if host not in (jwxt_host.lower(), wfw_host.lower()):
        return False
    if is_auth_url(final_url, authserver_host=authserver_host):
        return False

    text = response.text or ""
    if not text.strip():
        return False
    if is_login_page_html(text) or is_reauth_page_html(text):
        return False

    # wfw 根路径默认代理到 file.gdou.edu.cn，不能当作教务系统已登录页面
    if host == wfw_host.lower() and (parsed.path or "/") == "/":
        return False
    return True


def classify_login_response(
    html: str,
    url: str = "",
    *,
    jwxt_host: str = "jw.gdou.edu.cn",
    authserver_host: str = "authserver.gdou.edu.cn",
    wfw_host: str = "wfw.gdou.edu.cn",
) -> AuthResult:
    if is_reauth_url(url) or is_reauth_page_html(html):
        return AuthResult(
            AuthStatus.NEED_MANUAL_VERIFICATION,
            "统一身份认证平台要求二次验证",
            ChallengeType.MFA_REQUIRED,
            url=url,
        )

    if is_auth_url(url, authserver_host=authserver_host) or is_login_page_html(html):
        error_text = extract_login_error(html)
        lower_err = error_text.lower()
        if error_text and any(marker in lower_err for marker in _CAPTCHA_ERROR_MARKERS):
            return AuthResult(
                AuthStatus.NEED_MANUAL_VERIFICATION,
                error_text,
                ChallengeType.IMAGE_CAPTCHA,
                url=url,
            )
        if error_text and any(marker in lower_err for marker in _INVALID_CREDENTIAL_MARKERS):
            return AuthResult(
                AuthStatus.INVALID_CREDENTIALS,
                error_text,
                url=url,
            )
        return AuthResult(
            AuthStatus.AUTHENTICATION_REQUIRED,
            error_text or "当前未获得有效登录态",
            url=url,
        )

    parsed = urlparse(url or "")
    if (parsed.hostname or "").lower() in (jwxt_host.lower(), wfw_host.lower()):
        return AuthResult(AuthStatus.SUCCESS, "已获得教务系统登录态", url=url)

    return AuthResult(AuthStatus.UNKNOWN_ERROR, "无法判断登录结果", url=url)
