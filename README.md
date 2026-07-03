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

## 快捷接口

已预留这些接口方法：

```python
from gdou_jwxt import JwxtClient, JwxtConfig

client = JwxtClient(
    username="学号",
    password="密码",
    config=JwxtConfig(headless=True),
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

```python
if auth.ok:
    for item in exams.items:
        print(item.course_name, item.exam_time, item.classroom)

    for course in timetable.courses:
        print(course.course_name, course.weekday_name, course.periods, course.classroom)
```

`query_grades()`、`query_timetable()`、`query_mobile_timetable()` 和 `query_exam_schedule()` 已有默认 URL。`academic_year` 传 `2025-2026` 这种学年格式，内部会自动转换成教务系统需要的 `xnm=2025`。

成绩查询参数里 `academic_year` 对应 `xnm`，`term` 对应 `xqm`，`course_mark` 对应 `kcbj`。

课表查询参数里 `academic_year` 对应 `xnm`，`term` 对应 `xqm`，`view_type` 对应 `kzlx`，`student_code` 对应 `xsdm`，`course_category` 对应 `kclbdm`，`course_type` 对应 `kclxdm`。

移动端课表查询参数里 `academic_year` 对应 `xnm`，`term` 对应 `xqm`，`campus_id` 对应 `xqh_id`。

考试日程查询参数里 `academic_year` 对应 `xnm`，`term` 对应 `xqm`，`exam_name_id` 对应 `ksmcdmb_id`，`course_code` 对应 `kch`，`course_name` 对应 `kc`，`exam_date` 对应 `ksrq`，`department_id` 对应 `kkbm_id`。

其他接口需要在 `JwxtConfig` 里补 URL：

```python
config = JwxtConfig(
    headless=True,
    student_info_url="待补充",
    training_plan_url="待补充",
    course_selection_url="待补充",
    empty_classroom_url="待补充",
)
```

也可以直接请求任意已知接口：

```python
auth, data = client.query_endpoint("接口 URL", data={"xnm": "2025"})
```
