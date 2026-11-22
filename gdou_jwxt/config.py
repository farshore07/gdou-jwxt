from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

from .models import MfaMethod, NetworkMode

DEFAULT_COOKIE_DIR = Path(".gdou_jwxt")
DEFAULT_COOKIE_FILENAME = "cookies.json"
_DEFAULT_COOKIE_FILE = DEFAULT_COOKIE_DIR / DEFAULT_COOKIE_FILENAME


@dataclass(frozen=True)
class JwxtConfig:
    jwxt_base_url: str = "https://jw.gdou.edu.cn"
    jwxt_home_url: str = "https://jw.gdou.edu.cn/xtgl/index_initMenu.html"
    sso_service_url: str = "https://jw.gdou.edu.cn/sso/jziotlogin"
    authserver_base_url: str = "https://authserver.gdou.edu.cn/authserver"
    wfw_base_url: str = "https://wfw.gdou.edu.cn"
    netcheck_url: str = "https://netcheck.gdou.edu.cn/go.php?code=jw"
    network_mode: NetworkMode = NetworkMode.CAMPUS
    grade_url: str = "https://jw.gdou.edu.cn/cjcx/cjcx_cxXsgrcj.html?doType=query&gnmkdm=N305005"
    timetable_url: str = "https://jw.gdou.edu.cn/kbcx/xskbcx_cxXsgrkb.html?gnmkdm=N2151"
    mobile_timetable_url: str = "https://jw.gdou.edu.cn/kbcx/xskbcxMobile_cxXsKb.html?gnmkdm=N2154"
    exam_schedule_url: str = "https://jw.gdou.edu.cn/kwgl/kscx_cxXsksxxIndex.html?doType=query&gnmkdm=N358105"
    student_info_url: str = ""
    training_plan_url: str = ""
    course_selection_url: str = ""
    empty_classroom_url: str = ""
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
    timeout: float = 15.0
    cookie_dir: Path | str | None = None
    cookie_file: Path | str | None = _DEFAULT_COOKIE_FILE
    mfa_method: MfaMethod = MfaMethod.AUTO
    trust_device: bool = True
    device_fingerprint: str = ""

    @property
    def wfw_service_url(self) -> str:
        return f"{self.wfw_base_url.rstrip('/')}/"

    @property
    def wfw_jwxt_init_url(self) -> str:
        return f"{self.wfw_base_url.rstrip('/')}/{self.jwxt_base_url.rstrip('/')}"

    @property
    def wfw_jwxt_forward_url(self) -> str:
        return f"{self.wfw_base_url.rstrip('/')}/xtgl/dl_loginForward.html?language="

    def authserver_base_for(self, mode: NetworkMode) -> str:
        # authserver.gdou.edu.cn 在校内与公网均可直连，且 wfw 代理不完整支持 POST /authserver/login
        return self.authserver_base_url.rstrip("/")

    def service_url_for(self, mode: NetworkMode) -> str:
        if mode == NetworkMode.EXTERNAL:
            return self.wfw_service_url
        return self.sso_service_url

    def authserver_login_url_for(self, mode: NetworkMode) -> str:
        base = self.authserver_base_for(mode)
        return f"{base}/login?service={quote(self.service_url_for(mode), safe='')}"

    @property
    def resolved_cookie_file(self) -> Path | None:
        if self.cookie_file is None:
            return None
        file_path = Path(self.cookie_file)
        if self.cookie_dir is not None:
            base_dir = Path(self.cookie_dir)
            if file_path == _DEFAULT_COOKIE_FILE:
                return base_dir / DEFAULT_COOKIE_FILENAME
            if not file_path.is_absolute():
                return base_dir / file_path
        return file_path

    @property
    def authserver_login_url(self) -> str:
        return self.authserver_login_url_for(self.network_mode)

    @property
    def headers(self) -> dict[str, str]:
        return {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
