from __future__ import annotations

import time
from collections.abc import Callable

import cv2
import numpy as np
import requests

from .captcha_solver import get_image_bytes, solve_slider
from .config import JwxtConfig
from .detector import classify_login_response
from .models import AuthResult, AuthStatus

STEALTH_JS = """
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
Object.defineProperty(navigator, 'plugins', {
    get: () => {
        const arr = [
            {name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer', length: 1},
            {name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', length: 1},
            {name: 'Native Client', filename: 'internal-nacl-plugin', length: 2},
        ];
        arr.item = (i) => arr[i] || null;
        arr.namedItem = (n) => arr.find(p => p.name === n) || null;
        arr.refresh = () => {};
        Object.defineProperty(arr, 'length', {get: () => 3});
        return arr;
    }
});
if (!window.chrome) { window.chrome = {}; }
if (!window.chrome.runtime) { window.chrome.runtime = {}; }
if (!window.chrome.runtime.connect) { window.chrome.runtime.connect = () => ({disconnect: () => {}}); }
const origQuery = window.navigator.permissions.query;
window.navigator.permissions.query = (params) => {
    if (params.name === 'notifications') {
        return Promise.resolve({state: 'prompt', onchange: null});
    }
    return origQuery(params);
};
Object.defineProperty(navigator, 'languages', {get: () => ['zh-CN', 'zh', 'en']});
"""

CHROME_ARGS = [
    "--disable-blink-features=AutomationControlled",
    "--disable-features=IsolateOrigins,site-per-process",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-infobars",
    "--disable-dev-shm-usage",
    "--disable-setuid-sandbox",
    "--no-sandbox",
    "--disable-accelerated-2d-canvas",
    "--disable-gpu",
]


class AutoLogin:
    def __init__(
        self,
        config: JwxtConfig | None = None,
        page_factory: Callable[[], object] | None = None,
    ) -> None:
        self.config = config or JwxtConfig()
        self.page_factory = page_factory

    def login(
        self,
        username: str,
        password: str,
        max_retries: int = 3,
        timeout_seconds: int = 120,
        poll_interval: float = 1.0,
    ) -> tuple[AuthResult, requests.Session | None]:
        last_error = "等待跳转超时"
        for _ in range(max_retries):
            page = self._create_page()
            session = requests.Session()
            session.headers.update(self.config.headers)
            try:
                page.get(self.config.jwxt_login_url)
                self._inject_stealth(page)
                self._fill_login_form(page, username, password)
                if self._has_slider_captcha(page) and not self._try_solve_slider(page):
                    last_error = "滑块识别失败"
                    continue
                self._click_submit(page)
                deadline = time.monotonic() + timeout_seconds
                while time.monotonic() < deadline:
                    current_url = str(getattr(page, "url", "") or "")
                    result = classify_login_response(self._html(page), current_url)
                    if result.ok:
                        self._copy_cookies(page, session)
                        return result, session
                    if result.status in {AuthStatus.INVALID_CREDENTIALS, AuthStatus.NEED_MANUAL_VERIFICATION}:
                        return result, None
                    time.sleep(poll_interval)
                self._copy_cookies(page, session)
                if session.cookies:
                    result = self._validate_with_session(session)
                    if result.ok:
                        return result, session
                    last_error = result.message
            finally:
                close = getattr(page, "quit", None)
                if callable(close):
                    close()
        return AuthResult(AuthStatus.VERIFICATION_INCOMPLETE, last_error), None

    def _create_page(self) -> object:
        if self.page_factory:
            return self.page_factory()
        try:
            from DrissionPage import ChromiumOptions, ChromiumPage
        except ImportError as exc:
            raise RuntimeError("未安装 DrissionPage，无法执行自动登录") from exc

        options = ChromiumOptions()
        for arg in CHROME_ARGS:
            options.set_argument(arg)
        options.set_argument("--remote-debugging-port", "0")
        return ChromiumPage(options)

    def _inject_stealth(self, page: object) -> None:
        try:
            run_cdp = getattr(page, "run_cdp", None)
            if callable(run_cdp):
                run_cdp("Page.addScriptToEvaluateOnNewDocument", source=STEALTH_JS)
            run_js = getattr(page, "run_js", None)
            if callable(run_js):
                run_js(STEALTH_JS)
        except Exception:
            pass

    def _fill_login_form(self, page: object, username: str, password: str) -> None:
        for selector in ("#yhm", "#username", "input[name='username']", "input[name='yhm']"):
            element = self._find(page, selector)
            if element:
                element.input(username)
                break
        for selector in ("#mm", "#password", "input[name='password']", "input[name='mm']"):
            element = self._find(page, selector)
            if element:
                element.input(password)
                break

    def _click_submit(self, page: object) -> bool:
        for selector in ("#dl", "button[type='submit']", "input[type='submit']", "#loginButton"):
            element = self._find(page, selector)
            if element:
                element.click()
                return True
        return False

    def _has_slider_captcha(self, page: object) -> bool:
        return bool(self._find(page, ".zfdun_bgimg_img") or self._find(page, ".zfdun_slider_bar_btn"))

    def _try_solve_slider(self, page: object) -> bool:
        try:
            bg_element = page.ele(".zfdun_bgimg_img", timeout=3)
            piece_element = page.ele(".zfdun_bgimg_jigsaw", timeout=3)
            slider_button = page.ele(".zfdun_slider_bar_btn", timeout=3)
            if not bg_element or not piece_element or not slider_button:
                return False
            current_url = str(getattr(page, "url", "") or "")
            cookies = page.cookies() if callable(getattr(page, "cookies", None)) else []
            cookie_text = "; ".join(f"{item['name']}={item['value']}" for item in cookies)
            bg_bytes = get_image_bytes(bg_element, current_url, cookie_text)
            piece_bytes = get_image_bytes(piece_element, current_url, cookie_text)
            distance = solve_slider(bg_bytes, piece_bytes)
            if distance is None:
                return False
            left = piece_element.style("left") if callable(getattr(piece_element, "style", None)) else "0"
            initial_offset = float((left or "0").replace("px", "").strip())
            web_width = bg_element.rect.size[0] if getattr(bg_element, "rect", None) else 300.0
            img = cv2.imdecode(np.frombuffer(bg_bytes, np.uint8), cv2.IMREAD_COLOR)
            image_width = img.shape[1] if img is not None else web_width
            drag_distance = max(10, min((distance * (web_width / image_width)) - initial_offset, web_width - 10))
            slider_button.drag(drag_distance, 0, duration=1.5)
            return True
        except Exception:
            return False

    def _html(self, page: object) -> str:
        html = getattr(page, "html", "")
        return str(html() if callable(html) else html or "")

    def _validate_with_session(self, session: requests.Session) -> AuthResult:
        try:
            response = session.get(
                self.config.jwxt_home_url,
                headers=self.config.headers,
                timeout=self.config.timeout,
            )
            return classify_login_response(response.text, response.url)
        except requests.RequestException as exc:
            return AuthResult(AuthStatus.NETWORK_ERROR, str(exc))

    def _copy_cookies(self, page: object, session: requests.Session) -> None:
        try:
            cookies = page.cookies() if callable(getattr(page, "cookies", None)) else []
        except Exception:
            return
        for cookie in cookies or []:
            if not isinstance(cookie, dict) or not cookie.get("name"):
                continue
            session.cookies.set(
                cookie["name"],
                cookie.get("value", ""),
                domain=cookie.get("domain") or "",
                path=cookie.get("path") or "/",
            )

    def _find(self, page: object, selector: str) -> object | None:
        finder = getattr(page, "ele", None)
        if not callable(finder):
            return None
        return finder(selector, timeout=0)
