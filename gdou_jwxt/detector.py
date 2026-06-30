from __future__ import annotations

from .models import AuthResult, AuthStatus, ChallengeType


def detect_challenge(html: str, url: str = "") -> AuthResult | None:
    text = (html or "").lower()
    lower_url = (url or "").lower()

    slider_markers = (
        "zfdun_slider",
        "zfdun_bgimg",
        "slider",
        "滑块",
        "jigsaw",
    )
    if any(marker in text or marker in lower_url for marker in slider_markers):
        return AuthResult(
            AuthStatus.NEED_MANUAL_VERIFICATION,
            "页面要求完成滑块验证码",
            ChallengeType.SLIDER_CAPTCHA,
            url,
        )

    secondary_markers = (
        "二次验证",
        "安全验证",
        "动态码",
        "短信验证码",
        "otp",
        "mfa",
        "two-factor",
        "verification",
    )
    if any(marker in text for marker in secondary_markers):
        return AuthResult(
            AuthStatus.NEED_MANUAL_VERIFICATION,
            "统一身份认证平台要求二次验证",
            ChallengeType.SECONDARY_VERIFICATION,
            url,
        )

    return None


def classify_login_response(html: str, url: str = "") -> AuthResult:
    challenge = detect_challenge(html, url)
    if challenge:
        return challenge

    text = html or ""
    lower_text = text.lower()
    lower_url = (url or "").lower()

    invalid_markers = ("用户名或密码", "密码错误", "账号或密码", "invalid password", "bad credentials")
    if any(marker in lower_text for marker in invalid_markers):
        return AuthResult(AuthStatus.INVALID_CREDENTIALS, "账号或密码错误", url=url)

    login_markers = ("login_slogin", 'name="password"', "请输入密码")
    if any(marker in lower_url or marker in lower_text for marker in login_markers):
        return AuthResult(AuthStatus.SESSION_EXPIRED, "当前未获得有效登录态", url=url)

    success_markers = ("退出", "logout", "个人信息", "学生课表", "成绩")
    if "jw.gdou.edu.cn" in lower_url and any(marker in lower_text for marker in success_markers):
        return AuthResult(AuthStatus.SUCCESS, "已获得教务系统登录态", url=url)

    if "jw.gdou.edu.cn" in lower_url:
        return AuthResult(AuthStatus.SUCCESS, "已跳转到教务系统", url=url)

    return AuthResult(AuthStatus.UNKNOWN_ERROR, "无法判断登录结果", url=url)
