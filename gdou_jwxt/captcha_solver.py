from __future__ import annotations

import base64
from typing import Any
from urllib.parse import urljoin
from urllib.request import Request, urlopen

import cv2
import numpy as np


# ---------------------------------------------------------------------------
# image helpers
# ---------------------------------------------------------------------------

def decode_data_url(data_url: str) -> bytes | None:
    if not data_url or not data_url.lower().startswith("data:"):
        return None
    try:
        _, data = data_url.split(",", 1)
        return base64.b64decode(data)
    except Exception:
        return None


def fetch_url_bytes(url: str, referer: str = "", cookies: str = "") -> bytes:
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
    }
    if referer:
        headers["Referer"] = referer
    if cookies:
        headers["Cookie"] = cookies
    req = Request(url, headers=headers)
    with urlopen(req, timeout=8) as resp:
        if resp.status == 200:
            return resp.read()
        raise ValueError(f"HTTP 状态码异常: {resp.status}")


def _src_to_bytes(ele: Any, page_url: str, cookies: str) -> bytes:
    src = (ele.attr("src") if hasattr(ele, "attr") else None) or ""
    src = src.strip()
    if src.lower().startswith("data:"):
        decoded = decode_data_url(src)
        if decoded:
            return decoded
        raise ValueError("Base64 Data URL 解码失败")
    if src.startswith("//"):
        full_url = f"https:{src}"
    elif src.startswith("/"):
        full_url = urljoin(page_url, src)
    elif not src.startswith("http"):
        full_url = urljoin(page_url, src)
    else:
        full_url = src
    if full_url.startswith("http://") or full_url.startswith("https://"):
        return fetch_url_bytes(full_url, page_url, cookies)
    raise ValueError(f"不支持的图片路径格式: {full_url}")


def get_image_bytes(ele: Any, page_url: str = "", cookies: str = "") -> bytes:
    try:
        return _src_to_bytes(ele, page_url, cookies)
    except Exception:
        pass
    shot = getattr(ele, "get_screenshot", None)
    if callable(shot):
        result = shot(as_bytes=True)
        if result:
            return result
    raise RuntimeError("无法从元素获取图片数据")


def _crop_piece_to_alpha(tp_bytes: bytes) -> tuple[bytes, int]:
    """裁剪拼图块透明边，返回裁剪后的 PNG 和宽度."""
    img = cv2.imdecode(np.frombuffer(tp_bytes, np.uint8), cv2.IMREAD_UNCHANGED)
    if img is None:
        return tp_bytes, 60
    if len(img.shape) == 3 and img.shape[2] == 4:
        alpha = img[:, :, 3]
        ys, xs = np.where(alpha > 10)
        if xs.size > 0 and ys.size > 0:
            x_min, x_max = xs.min(), xs.max()
            y_min, y_max = ys.min(), ys.max()
            cropped = img[y_min : y_max + 1, x_min : x_max + 1]
            piece_width = x_max - x_min + 1
            _, encoded = cv2.imencode(".png", cropped)
            return encoded.tobytes(), piece_width
    return tp_bytes, img.shape[1]


# ---------------------------------------------------------------------------
# gap detection — template matching on Canny edges
# ---------------------------------------------------------------------------

def solve_slider(bg_bytes: bytes, tp_bytes: bytes) -> int | None:
    """用 Canny 边缘模板匹配识别缺口横向偏移."""
    bg = cv2.imdecode(np.frombuffer(bg_bytes, np.uint8), cv2.IMREAD_COLOR)
    tp = cv2.imdecode(np.frombuffer(tp_bytes, np.uint8), cv2.IMREAD_COLOR)
    if bg is None or tp is None:
        return None

    # 裁剪拼图去透明边
    tp_cropped, _ = _crop_piece_to_alpha(tp_bytes)

    bg_gray = cv2.cvtColor(bg, cv2.COLOR_BGR2GRAY)
    tp_img = cv2.imdecode(np.frombuffer(tp_cropped, np.uint8), cv2.IMREAD_COLOR)
    if tp_img is None:
        return None
    tp_gray = cv2.cvtColor(tp_img, cv2.COLOR_BGR2GRAY)

    bg_edges = cv2.Canny(cv2.GaussianBlur(bg_gray, (3, 3), 0), 30, 100)
    tp_edges = cv2.Canny(cv2.GaussianBlur(tp_gray, (3, 3), 0), 30, 100)

    h_tp, w_tp = tp_edges.shape[:2]
    h_bg, w_bg = bg_edges.shape[:2]
    if w_tp > w_bg or h_tp > h_bg:
        return None

    result = cv2.matchTemplate(bg_edges, tp_edges, cv2.TM_CCOEFF_NORMED)
    _, max_val, _, max_loc = cv2.minMaxLoc(result)

    if max_val < 0.15:
        return None
    return int(max_loc[0])
