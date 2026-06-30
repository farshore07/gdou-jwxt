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
