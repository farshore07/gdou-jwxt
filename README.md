# gdou-jwxt

广东海洋大学教务系统全自动登录 Python 模块。

## 安装

基础安装：

```powershell
pip install -e .
```

## 导入

```python
from gdou_jwxt import AutoLogin, Authenticator, JwxtClient, JwxtConfig
```

## 无头登录

```python
from gdou_jwxt import Authenticator, JwxtConfig

auth = Authenticator(config=JwxtConfig(headless=True))
result = auth.login("学号", "密码")
```

## 会话保持

登录成功后会把 Cookie 保存到程序运行目录：

```text
.gdou_jwxt/cookies.json
```

下次调用 `login()` 会先尝试复用 Cookie，失效后再重新自动登录。
