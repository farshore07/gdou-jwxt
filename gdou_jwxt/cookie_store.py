from __future__ import annotations

import json
import os
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests
from requests.cookies import create_cookie


@dataclass
class CookieStore:
    path: Path | str | None

    def __post_init__(self) -> None:
        if isinstance(self.path, str):
            self.path = Path(self.path)

    def load(self, session: requests.Session) -> bool:
        if self.path is None or not self.path.exists():
            return False
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False

        cookies = payload.get("cookies")
        if not isinstance(cookies, list):
            return False

        now = time.time()
        loaded = False
        for item in cookies:
            if not isinstance(item, dict) or not item.get("name"):
                continue
            expires = item.get("expires")
            if isinstance(expires, (int, float)) and expires <= now:
                continue
            cookie = create_cookie(
                name=str(item["name"]),
                value=str(item.get("value", "")),
                domain=str(item.get("domain") or ""),
                path=str(item.get("path") or "/"),
                secure=bool(item.get("secure", False)),
                expires=expires if isinstance(expires, (int, float)) else None,
            )
            session.cookies.set_cookie(cookie)
            loaded = True
        return loaded

    def save(self, session: requests.Session) -> None:
        if self.path is None:
            return
        now = time.time()
        cookies: list[dict[str, Any]] = []
        for cookie in session.cookies:
            if not cookie.name:
                continue
            if cookie.expires is not None and cookie.expires <= now:
                continue
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
        content = json.dumps({"cookies": cookies}, ensure_ascii=False, indent=2)

        fd, tmp_name = tempfile.mkstemp(prefix=".cookies_", suffix=".tmp", dir=str(self.path.parent))
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(content)
            try:
                os.chmod(tmp_path, 0o600)
            except OSError:
                pass
            os.replace(tmp_path, self.path)
        except Exception:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise

    def clear(self) -> None:
        if self.path is None:
            return
        try:
            self.path.unlink(missing_ok=True)
        except OSError:
            pass
