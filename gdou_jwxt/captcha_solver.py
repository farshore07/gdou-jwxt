from __future__ import annotations

import base64
import random
from typing import Any
from urllib.parse import urljoin
from urllib.request import Request, urlopen

import cv2
import ddddocr
import numpy as np

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


def crop_piece_image(tp_bytes: bytes) -> tuple[bytes, int]:
    """裁剪拼图块透明边，返回裁剪后的图片和宽度。"""
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

def detect_gap_by_ddddocr(
    tp_bytes: bytes, bg_bytes: bytes
) -> dict[str, Any] | None:
    """用 ddddocr 识别缺口位置。"""
    det = ddddocr.DdddOcr(det=False, ocr=False, show_ad=False)
    try:
        res_complex = det.slide_match(tp_bytes, bg_bytes, simple_target=False)
    except Exception:
        res_complex = None
    try:
        res_simple = det.slide_match(tp_bytes, bg_bytes, simple_target=True)
    except Exception:
        res_simple = None

    valid = [r for r in (res_complex, res_simple) if r and "target" in r]
    if not valid:
        return None
    best = max(valid, key=lambda r: float(r.get("confidence") or 0.0))
    return {
        "target": best["target"],
        "confidence": float(best.get("confidence") or 0.0),
        "method": "ddddocr",
    }


def detect_gap_by_template(
    bg_bytes: bytes, tp_bytes: bytes
) -> dict[str, Any] | None:
    """用模板匹配识别缺口位置。"""
    bg = cv2.imdecode(np.frombuffer(bg_bytes, np.uint8), cv2.IMREAD_COLOR)
    tp = cv2.imdecode(np.frombuffer(tp_bytes, np.uint8), cv2.IMREAD_COLOR)
    if bg is None or tp is None:
        return None

    bg_gray = cv2.cvtColor(bg, cv2.COLOR_BGR2GRAY)
    tp_gray = cv2.cvtColor(tp, cv2.COLOR_GRAY2BGR if len(tp.shape) == 2 else cv2.COLOR_BGR2GRAY)
    if len(tp_gray.shape) == 3:
        tp_gray = cv2.cvtColor(tp_gray, cv2.COLOR_BGR2GRAY)

    bg_edges = cv2.Canny(cv2.GaussianBlur(bg_gray, (3, 3), 0), 30, 100)
    tp_edges = cv2.Canny(cv2.GaussianBlur(tp_gray, (3, 3), 0), 30, 100)

    h_tp, w_tp = tp_edges.shape[:2]
    h_bg, w_bg = bg_edges.shape[:2]

    if w_tp > w_bg or h_tp > h_bg:
        return None

    result = cv2.matchTemplate(bg_edges, tp_edges, cv2.TM_CCOEFF_NORMED)
    _, max_val, _, max_loc = cv2.minMaxLoc(result)

    x = max_loc[0]
    y = max_loc[1] + h_tp // 2

    if max_val < 0.15:
        return None

    return {
        "target": [int(x), int(y)],
        "confidence": float(max_val),
        "method": "template",
    }


def detect_gap_by_edge(
    bg_bytes: bytes, piece_width: int
) -> dict[str, Any] | None:
    """用边缘特征识别缺口位置。"""
    img = cv2.imdecode(np.frombuffer(bg_bytes, np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        return None

    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
    gray = clahe.apply(gray)
    blurred = cv2.GaussianBlur(gray, (3, 3), 0)

    edges = cv2.Canny(blurred, 30, 100)

    sobel_x = cv2.Sobel(blurred, cv2.CV_64F, 1, 0, ksize=3)
    sobel_y = cv2.Sobel(blurred, cv2.CV_64F, 0, 1, ksize=3)
    gradient_angle = np.arctan2(np.abs(sobel_y), np.abs(sobel_x))
    vertical_mask = (gradient_angle > np.pi / 6) & (gradient_angle < 5 * np.pi / 6)
    edges_weighted = edges.copy()
    edges_weighted[vertical_mask] = 255
    edges = edges_weighted

    kernel_size = max(piece_width // 6, 3)
    kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (kernel_size, kernel_size))
    closed = cv2.morphologyEx(edges, cv2.MORPH_CLOSE, kernel, iterations=2)

    contours, _ = cv2.findContours(closed, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    best = None
    best_score = -1.0
    h, w = img.shape[:2]

    for c in contours:
        x, y, cw, ch = cv2.boundingRect(c)
        area = cv2.contourArea(c)
        if cw < 20 or ch < 20:
            continue
        ratio = cw / max(ch, 1)
        if ratio < 0.3 or ratio > 2.5:
            continue
        if x < 5 or y < 3 or (x + cw) > (w - 5) or (y + ch) > (h - 5):
            continue
        solidity = area / (cw * ch)
        if solidity < 0.25:
            continue
        score = area * solidity
        if x > int(w * 0.2):
            score *= 1.5
        if score > best_score:
            best_score = score
            best = (x, y, cw, ch)

    if not best:
        return None

    x, y, cw, ch = best
    return {
        "target": [int(x), int(y + ch // 2)],
        "confidence": min(best_score / 5000.0, 1.0),
        "method": "edge",
        "box": [int(x), int(y), int(cw), int(ch)],
    }

def consensus(
    results: list[dict[str, Any] | None], image_width: int
) -> dict[str, Any] | None:
    """合并多种识别结果，选出最可信的位置。"""
    valid = [r for r in results if r and "target" in r]
    if not valid:
        return None
    if len(valid) == 1:
        return valid[0]

    xs = [int(r["target"][0]) for r in valid]
    confs = [float(r.get("confidence") or 0.0) for r in valid]

    if len(valid) == 2:
        if abs(xs[0] - xs[1]) <= 15:
            total = confs[0] + confs[1]
            w = xs[0] * confs[0] / total + xs[1] * confs[1] / total if total > 0 else xs[0]
            return {
                "target": [int(w), int(valid[0]["target"][1])],
                "confidence": max(confs),
                "method": "consensus",
            }
        methods = [r["method"] for r in valid]
        for preferred in ("template", "ddddocr", "edge"):
            if preferred in methods:
                return valid[methods.index(preferred)]

    pairs = [(0, 1), (0, 2), (1, 2)]
    spreads = [(abs(xs[a] - xs[b]), a, b) for a, b in pairs]
    spreads.sort()

    min_spread, a, b = spreads[0]
    if min_spread <= 15:
        w = (xs[a] + xs[b]) / 2.0
        return {
            "target": [int(w), int(valid[0]["target"][1])],
            "confidence": max(confs[a], confs[b]),
            "method": f"consensus({valid[a]['method']}+{valid[b]['method']})",
        }

    methods = [r["method"] for r in valid]
    for preferred in ("template", "ddddocr", "edge"):
        if preferred in methods:
            return valid[methods.index(preferred)]

    return valid[0]

def solve_slider(bg_bytes: bytes, tp_bytes: bytes) -> int | None:
    """返回滑块缺口的横向偏移。"""
    tp_bytes_cropped, piece_width = crop_piece_image(tp_bytes)

    ocr_res = detect_gap_by_ddddocr(tp_bytes_cropped, bg_bytes)
    tpl_res = detect_gap_by_template(bg_bytes, tp_bytes_cropped)
    edge_res = detect_gap_by_edge(bg_bytes, piece_width)

    img = cv2.imdecode(np.frombuffer(bg_bytes, np.uint8), cv2.IMREAD_COLOR)
    image_width = img.shape[1] if img is not None else 360

    result = consensus([ocr_res, tpl_res, edge_res], image_width)
    if not result:
        return None
    return int(result["target"][0])

def generate_movement_track(distance: float) -> list[dict[str, float]]:
    """生成较接近人工操作的拖动轨迹。"""
    track: list[dict[str, float]] = []

    track.append({"x": 0, "y": 0, "t": random.uniform(0.10, 0.30)})
    for _ in range(random.randint(1, 3)):
        track.append({
            "x": random.uniform(-2, 2),
            "y": random.uniform(-1.5, 1.5),
            "t": random.uniform(0.006, 0.012),
        })

    t = random.uniform(0.006, 0.012)
    v = 0.0
    current = 0.0
    decel_start = distance * random.uniform(0.55, 0.70)
    mid = distance * random.uniform(0.75, 0.88)
    pause_points = sorted([
        random.uniform(distance * 0.2, distance * 0.4),
        random.uniform(distance * 0.55, distance * 0.75),
    ][:random.randint(1, 2)])

    while current < distance:
        if current < decel_start:
            a = 0.006 + random.uniform(-0.003, 0.005)
        elif current < mid:
            a = 0.001 + random.uniform(-0.002, 0.004)
        else:
            a = -0.005 + random.uniform(-0.004, 0.003)

        v = max(v + a, 0.03)
        step = v * t + 0.5 * a * t * t

        if current + step >= distance:
            step = distance - current
            if step < 0.1:
                break

        current += step
        track.append({
            "x": round(current, 2),
            "y": round(random.uniform(-1.5, 1.5), 2),
            "t": t,
        })

        if pause_points and current >= pause_points[0]:
            track.append({
                "x": round(current + random.uniform(-1, 1), 2),
                "y": round(random.uniform(-1, 1.5), 2),
                "t": random.uniform(0.05, 0.15),
            })
            pause_points.pop(0)

        t = random.uniform(0.006, 0.012)

    overshoot = distance + random.uniform(2, 5)
    track.append({"x": round(overshoot, 2), "y": round(random.uniform(-1, 1), 2), "t": 0.05})
    track.append({"x": round(distance + random.uniform(-1.5, 0.5), 2), "y": round(random.uniform(-1, 1), 2), "t": 0.06})
    track.append({"x": distance, "y": 0, "t": 0.08})

    return track
