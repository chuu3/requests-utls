# 连接最大寿命与平滑替换

在同一个 Session 内，让过老的物理 TCP/TLS 连接停止接收新请求，待在途请求及响应体处理完成后关闭。支持 HTTP/2、HTTP/1.1 与 ALPN 回退；**默认关闭**。本功能尚未发布，需要包含此实现的 Go/native 引擎和 Python 包。

## 参数与接口

| Python `Session` / `AsyncSession` 参数 | Go `Options` 字段 | native JSON 字段 |
| --- | --- | --- |
| `max_connection_age` | `MaxConnectionAge` | `max_connection_age_ms` |
| `connection_age_jitter` | `ConnectionAgeJitter` | `connection_age_jitter_ms` |

- **最大寿命**：默认 `0`，关闭年龄限制。
- **随机提前量**：默认 `0`。每条连接创建时只采样一次，退休期限为 `创建时间 + 最大寿命 - uniform[0, jitter)`。
- **单位**：Python 为秒，Go 为 `time.Duration`，native 为整数毫秒。计龄从拨号前开始，包含 TCP、代理 CONNECT 和 TLS 握手时间，使用单调时钟。
- **校验**：启用时要求 `0 <= jitter < 最大寿命`；关闭时两者必须为 `0`。拒绝负数、非有限数和溢出。Python 还拒绝布尔值；正数向上取整到毫秒，取整后仍须满足不等式。native 上限为 `9,223,372,036,854` 毫秒。
- 参数在创建 Session 时设置，不能作为单次请求参数修改。Python 非法参数抛出 `InvalidRequestError`，Go 返回创建错误，native 返回 `InvalidInput`。

## 使用示例

以下示例假设已准备好对应语言的 `profile`；`60 / 10` 只是试验值，不是生产默认值。

```python
from requests_utls import Session, AsyncSession

with Session(profile=profile, max_connection_age=60, connection_age_jitter=10) as session:
    response = session.get("https://example.com/")

# 在 async 函数内：
async with AsyncSession(profile=profile, max_connection_age=60, connection_age_jitter=10) as session:
    response = await session.get("https://example.com/")
```

```go
session, err := requestsutls.NewSession(requestsutls.Options{
    Profile: profile,
    MaxConnectionAge: 60 * time.Second,
    ConnectionAgeJitter: 10 * time.Second,
})
// 处理 err；使用完成后调用 session.Close()。
```

其他语言调用 `ruts_session_create` 时，在已有配置 JSON 中增加：

```json
{"max_connection_age_ms": 60000, "connection_age_jitter_ms": 10000}
```

C 函数签名不变，ABI 版本仍为 1；旧引擎会拒绝这两个新 JSON 字段。Python 默认关闭时省略新字段，以兼容旧引擎。完整配置见 [native ABI](abi.md)。

## 行为与边界

- 到期后新请求使用其他连接；旧连接可以与新连接短暂共存，在途响应不会因年龄到期被主动截断。H2 的预留、stream 与响应体均纳入关闭判断；H1 保留独占所有权直到响应处理结束。
- 保留 Session、静态 Cookie 配置、代理身份、TLS profile 与会话恢复缓存；不新增 Cookie 自动维护。总超时、取消、并发限制和已有安全重试规则不变，不因年龄到期重放已发送请求。
- 空闲连接在取用、归还或已有空闲清理时处理到期，无须每条连接常驻任务。`Session.close()` / Go `Close()` 同时清理正在使用和退出复用的连接。
- 新连接在完成建连前就耗尽寿命时，返回错误而非无限重拨。Go 可检查 `ErrConnectionExpired`；Python 按传输错误处理。替换连接也可能拨号失败或超时。
- 这不是请求时限，也不能保证零 EOF。应为请求执行预留远端连接寿命余量；请求过长仍可能失败。行为验证见 [本地测试记录](verification.md#connection-lifetime--local-verification-2026-10-09)。
