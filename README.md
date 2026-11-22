# gdou-jwxt

广东海洋大学教务系统 Python 客户端（纯 HTTP 对接统一身份认证 `authserver.gdou.edu.cn` 与教务系统 `jw.gdou.edu.cn`）。

## 安装

```bash
pip install -e .
```

## 导入

```python
from gdou_jwxt import (
    Authenticator,
    AuthStatus,
    ChallengeType,
    JwxtClient,
    JwxtConfig,
    MfaMethod,
)
```

## 登录与二次验证

新设备首次登录统一身份认证时会触发企业微信或手机短信二次验证。本库支持以下两种交互方式：

### 1. 回调式同步登录（适合脚本 / CLI）

```python
from gdou_jwxt import Authenticator, JwxtConfig, MfaMethod

def ask_mfa_code(ctx) -> str:
    print(ctx.message)
    return input(f"请输入{ctx.method.label}（回车取消）: ").strip()

auth = Authenticator(
    config=JwxtConfig(mfa_method=MfaMethod.WECHAT, trust_device=True),
    mfa_code_provider=ask_mfa_code,
)
result = auth.login("学号", "密码")
```

### 2. 两步式状态机登录（适合 Web 后端 / Bot / GUI）

不传 `mfa_code_provider` 时，触发二次验证会立即返回绑定了独立会话的 `MfaContext`：

```python
from gdou_jwxt import Authenticator, AuthStatus, ChallengeType, MfaMethod

# 第一步：账密登录并触发发送验证码
auth = Authenticator()
res = auth.login("学号", "密码")

if res.status == AuthStatus.NEED_MANUAL_VERIFICATION and res.challenge_type == ChallengeType.MFA_REQUIRED:
    ctx = res.data
    auth.send_mfa_code(ctx, method=MfaMethod.WECHAT)  # 或 MfaMethod.SMS

    # 第二步：用户输入验证码后提交（trust_device=True 会标记可信设备）
    res = auth.verify_mfa_code(ctx, code="123456", trust_device=True)
```

> 多用户服务端场景请为每个用户创建独立的 `Authenticator` 与隔离的 `CookieStore`（或传入 `JwxtConfig(cookie_file=None)` 自行持久化）。

## 会话保持

登录成功后会将 `jw.gdou.edu.cn` 与 `authserver.gdou.edu.cn` 双域 Cookie（含可信设备指纹）默认保存到当前项目目录：

```text
.gdou_jwxt/cookies.json
```

支持自定义保存目录、指定具体文件路径或关闭本地文件存储：

```python
# 自定义保存目录（自动保存为 <目录>/cookies.json）
JwxtConfig(cookie_dir="./data/cookies")

# 自定义目录 + 文件名（多账号隔离）
JwxtConfig(cookie_dir="./data/cookies", cookie_file="student_a.json")

# 直接指定完整文件路径
JwxtConfig(cookie_file="/var/lib/jwxt/cookies.json")

# 关闭本地文件存储
JwxtConfig(cookie_file=None)
```

下次登录会优先复用已有 Cookie 或通过统一身份认证静默换票。

## 快捷接口

```python
from gdou_jwxt import JwxtClient, JwxtConfig, MfaMethod

client = JwxtClient(
    username="学号",
    password="密码",
    config=JwxtConfig(mfa_method=MfaMethod.WECHAT, trust_device=True),
    mfa_code_provider=lambda ctx: input(f"{ctx.message}\n请输入验证码: ").strip(),
)

auth, grades = client.query_grades(academic_year="2025-2026", term="12")
auth, timetable = client.query_timetable(academic_year="2025-2026", term="3")
auth, mobile_timetable = client.query_mobile_timetable(academic_year="2025-2026", term="3", campus_id="1")
auth, exams = client.query_exam_schedule(academic_year="2025-2026", term="12")
auth, info = client.query_student_info()
auth, plan = client.query_training_plan()
auth, courses = client.query_course_selection()
auth, rooms = client.query_empty_classrooms()
```

成绩和考试日程返回 `PageResult`，数据在 `items`；课表返回 `TimetableResult`，课程在 `courses`，学生信息在 `student_info`。

`query_grades()`、`query_timetable()`、`query_mobile_timetable()` 和 `query_exam_schedule()` 已内置默认 URL，且为已确认的只读查询接口（会话过期时允许自动重登后重试一次）；通用 `query_endpoint()` 的 `POST` 请求默认禁止自动重试，确认幂等后可显式传入 `retry_on_expired=True`，含文件上传的请求始终禁止自动重试。
