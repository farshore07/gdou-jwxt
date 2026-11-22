from __future__ import annotations

import base64
import random
import secrets

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# 与 authserver encrypt.js 中的 $aes_chars 保持一致
AES_CHARS = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"
_PREFIX_LEN = 64
_IV_LEN = 16


def _random_string(length: int, rng: random.Random | None = None) -> str:
    if rng is not None:
        return "".join(rng.choice(AES_CHARS) for _ in range(length))
    return "".join(secrets.choice(AES_CHARS) for _ in range(length))


def encrypt_password(
    password: str,
    salt: str,
    *,
    rng: random.Random | None = None,
) -> str:
    """按金智 IDS encrypt.js 规则加密密码。

    规则：
    1. 对 salt 去首尾空白后按 UTF-8 编码作为 AES 密钥（16/24/32 字节）；若 salt 为空返回原密码。
    2. 独立生成 64 个 ASCII 随机字符作为前缀拼接明文，独立生成 16 个 ASCII 随机字符作为 IV。
    3. AES-CBC + PKCS7 填充，返回无换行的标准 Base64 字符串。
    """
    key_text = (salt or "").strip()
    if not key_text:
        return password

    key = key_text.encode("utf-8")
    if len(key) not in (16, 24, 32):
        raise ValueError(f"无效的 AES 密钥长度: {len(key)} 字节（需要 16/24/32 字节）")

    prefix = _random_string(_PREFIX_LEN, rng)
    iv = _random_string(_IV_LEN, rng).encode("utf-8")
    plaintext = (prefix + password).encode("utf-8")

    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode("ascii")
