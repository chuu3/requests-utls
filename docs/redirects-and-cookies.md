# 为什么不自动跟随 Redirect，也不内置 Cookie Jar

requests-utls 把“下一次发送什么请求”的决定交给调用方。Go 引擎负责传输、协议、
连接复用和资源管理；Python 提供相应接口与响应解析。自动重定向和跨请求 Cookie
状态维护属于明确的设计边界，不是承诺稍后补齐的功能。

这项约定适用于 Go 和 Python、同步和异步调用。

## 当前到底支持什么

| 能力 | 当前行为 |
| --- | --- |
| 收到 3xx 响应 | 返回状态码、响应头和响应体，由调用方决定是否继续 |
| 自动跟随 Location | 不支持；Python 默认 `allow_redirects=False`，传 `True` 抛出 `InvalidRequestError` |
| 发送 Cookie | 支持显式 Cookie 请求头；Python 也支持 `cookies=` |
| 接收 Set-Cookie | 保留独立的响应字段，供调用方读取 |
| 解析响应 Cookie | Python 提供只读、仅属于当前响应的 `response.cookies` |
| 内置 Cookie Jar | 不支持，不自动存储、筛选或回填到下一次请求 |
| Session 的连接复用 | 支持；不依赖自动重定向或 Cookie Jar |

Python 的 Session `cookies=` 是静态默认值，不是 Cookie Jar。请求级 `cookies=`
按名称覆盖默认值；空字典不会清空默认值。响应的 Set-Cookie 不会修改这些默认值。
显式 Cookie 头不能与合并后非空的 `cookies=` 同时使用，包括非空 Session 默认值。

## 为什么不替调用方决定 Cookie 的优先级

手工输入和服务端状态同时存在时，库无法仅凭字段判断调用方的意图。

例如，应用保存了登录 Cookie，并在每次请求中写入：

```http
Cookie: session=old-value
```

服务端随后返回：

```http
Set-Cookie: session=new-value; Path=/; Secure
```

如果总是优先手工值，新值会被应用反复传入的旧值覆盖；如果总是优先 Jar，调用方
显式指定的值又可能无法生效。某些应用希望更新登录状态，另一些应用需要精确重放
之前的请求。两者都合理，但不能由一个隐式优先级同时表达。

删除比覆盖更容易产生歧义。假设服务端返回：

```http
Set-Cookie: session=; Max-Age=0; Path=/
```

即使 Jar 删除了该 Cookie，只要应用下一次仍传入 `session=old-value`，自动合并
就可能把旧值重新带回来。要阻止这种回填，还需要记录删除状态，并定义作用域、
生命周期、重新登录后的解除条件，以及何时允许显式覆盖。单纯增加
“优先 Set-Cookie / 优先手工 Cookie”两个选项，并不能解决这些问题。

因此，本库不提供 `cookie_policy`，也不尝试从请求头推断登录状态。
**如果调用方持续传入旧 Cookie，本库仍会发送那个值，即使之前收到过删除指令。**
关闭自动维护并不会自动修复调用方的旧状态；应用需要处理响应，并更新自己唯一的
状态来源，或明确选择忽略服务端更新。

## 为什么只读解析不等于 Cookie Jar

解析 Set-Cookie 能得到值、Domain、Path、Secure、Expires、Max-Age 等信息，
但决定是否接受、保存和发送它，还需要请求上下文和状态策略。
同名 Cookie 可以属于不同的 domain/path，不能只按名称合并。

Python 的 `response.cookies` 帮助读取这些信息，并保留可检查的过期、删除指令；
它不实现浏览器的完整接收和发送策略。需要维护 Cookie 状态的应用，应使用独立的
状态组件处理作用域、过期、删除等规则，而不是把只读解析结果当成可直接回填的 Jar。
Cookie 存储与发送规则可参考 [RFC 6265 §5.3–5.4](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.3)。

## 并发安全还需要明确状态更新顺序

同一个 Session 可以同时发出多个请求。假设请求 A、B 均使用旧登录状态，B 先返回
新 Cookie，A 稍后返回另一个值。给 Jar 加锁能保护数据结构，却不能决定哪个响应
代表业务上更新的状态。

线程安全的 Cookie Jar 完全可以实现，但账号隔离、状态版本、响应应用顺序以及
删除指令的处理，仍需要明确定义。requests-utls 不把这些共享的业务状态隐式挂到
传输 Session 上。应用也需要保证自己维护的 Cookie 状态在并发访问时安全。

## 为什么不自动跟随 Redirect

重定向需要构造下一次请求，而不只是替换 URL。调用方需要根据响应和应用策略决定：

- 如何解析相对 Location，是否允许访问目标地址，如何限制跳转次数和循环。
- 是否更换请求方法，保留或移除 body，以及是否能安全地再次发送该 body。
- 切换 origin 时哪些凭据和请求头可以继续使用，是否处理当前响应的 Set-Cookie。
- 如何选择下一跳的 Cookie、请求头和 `headers_order`。
- 多次请求是否共用一个总超时预算，以及何时终止整个操作。

不同重定向状态码的方法与 body 语义有区别，不能把所有 3xx 都写成“再次 GET”，
也不能把原请求完整复制给任意新地址。协议语义见
[RFC 9110 §15.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4)。

本库保留每次响应，让调用方在发送下一跳之前检查并作出决定。
自动重定向与 Cookie Jar 在技术上可以分别实现；这里同时交给上层，是为了让
完整请求流程和登录状态由同一个明确的策略层负责。

## 这个选择的代价与推荐分工

代价是调用方需要实现重定向和 Cookie 策略。需要类似浏览器或通用高层 HTTP 客户端
体验的应用，接入时会有更多工作。若多个业务都需要这些能力，应在应用共享的
适配层中统一实现并测试，避免每个调用点各写一套跳转循环。

建议由上层适配层维护唯一的 Cookie 状态来源：读取当前响应中的更新与删除指令，
按下一次请求的目标选择 Cookie，再显式传给底层。如果选择自己维护动态状态，
不要同时把同一份登录 Cookie 固定在 Session 默认值或每次都重放的静态请求头中。

需要精确重放的调用方，也可以选择完全不采纳服务端 Cookie 更新。这是调用方的
显式选择，不是库默认套用的优先级。

底层仍负责连接池、TLS、HTTP/2 流、协议要求的请求头处理、取消、响应读取和资源
清理。手动发起下一跳时，继续使用同一 Session，在连接满足复用条件时仍可复用。
TLS 会话恢复同样独立于 HTTP Cookie。**没有 Cookie Jar，不代表没有 Session 复用。**

当前 Python `timeout` 是单次请求的总预算。上层若希望一串跳转共用一个总预算，
应维护统一截止时间，把剩余时间传给下一次请求；预算耗尽时停止提交请求。

## Python 如何读取响应

下面只读取当前响应，不跟随跳转，也不回填 Cookie：

```python
from requests_utls import Profile, Session

with Session(profile=Profile.builtin("chrome_152")) as session:
    response = session.get("https://example.com/", allow_redirects=False)
    status = response.status_code
    locations = response.headers.get_list("Location")
    set_cookie_fields = response.headers.get_list("Set-Cookie")
    parsed_cookies = response.cookies
```

使用 `get_list("Set-Cookie")` 获取独立字段，不要用逗号拼接后的值解析 Cookie；
Expires 日期本身可能包含逗号。只读解析容器也不应被当成跨请求的登录状态。

具体接口约定见 [Go 使用说明](usage.md#redirect-and-cookie-ownership) 和
[Python 使用说明](https://github.com/chuu3/requests-utls-python/blob/main/docs/usage.md#redirect-and-cookie-ownership)。
