from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests


@dataclass
class CookieStore:
    path: Path

    def load(self, session: requests.Session) -> bool:
        if not self.path.exists():
            return False
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False

        cookies = payload.get("cookies")
        if not isinstance(cookies, list):
            return False

        loaded = False
        for item in cookies:
            if not isinstance(item, dict) or not item.get("name"):
                continue
            session.cookies.set(
                item["name"],
                item.get("value", ""),
                domain=item.get("domain") or "",
                path=item.get("path") or "/",
            )
            loaded = True
        return loaded

    def save(self, session: requests.Session) -> None:
        cookies: list[dict[str, Any]] = []
        for cookie in session.cookies:
            cookies.append(
                {
                    "name": cookie.name,
                    "value": cookie.value,
                    "domain": cookie.domain,
                    "path": cookie.path,
                    "secure": cookie.secure,
                    "expires": cookie.expires,
                }
            )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({"cookies": cookies}, ensure_ascii=False, indent=2), encoding="utf-8")
