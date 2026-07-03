from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class JwxtConfig:
    jwxt_login_url: str = "https://jw.gdou.edu.cn/xtgl/login_slogin.html"
    jwxt_home_url: str = "https://jw.gdou.edu.cn/xtgl/index_initMenu.html"
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
    headless: bool = False
    window_size: str = "1365,768"
    cookie_file: Path = Path.home() / ".gdou_jwxt" / "cookies.json"

    @property
    def headers(self) -> dict[str, str]:
        return {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
