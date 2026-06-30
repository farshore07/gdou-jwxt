from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class JwxtConfig:
    jwxt_login_url: str = "https://jw.gdou.edu.cn/xtgl/login_slogin.html"
    jwxt_home_url: str = "https://jw.gdou.edu.cn/xtgl/index_initMenu.html"
    grade_url: str = "https://jw.gdou.edu.cn/cjcx/cjcx_cxDgXscj.html"
    timetable_url: str = "https://jw.gdou.edu.cn/kbcx/xskbcx_cxXsgrkb.html"
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
    timeout: float = 15.0

    @property
    def headers(self) -> dict[str, str]:
        return {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
