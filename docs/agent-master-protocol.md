# Agent / Master 协议

Agent 向主控 `55555/udp` 发送 UTF-8 JSON，每个数据报是一条完整事件，单条不超过 60000 字节。Agent 还主动连接主控 `55556/tcp` 接收配置，组件安装下载通过该端口的独立临时连接转发，不增加 55557。主控 HTTP API 与前端分别使用 `10110/tcp`、`10111/tcp`。当前扩展保留 `version: 1` 和原有字段。

## 机器身份与配置

```yaml
server:
  - 172.22.0.100:55555
login:
  enabled: true
  mode: trigger
  source: journal
  poll_interval_ms: 1000 # 仅 mode: poll 时启用独立增量采集
setup:
  interval_seconds: 300
```

v0.6.6 自动识别本机 IP：Agent 读取已建立 TCP 连接的 LocalAddr，使用操作系统为到配置主控的路由选择的网卡地址，不做公网探测，也不从主机名推断。该地址用于 TCP 登记和全部 UDP 上报；Nginx/NAT 后的连接来源另存，不覆盖机器身份。TCP 未取得身份时，首个合格 UDP LocalAddr 经原子选择后由同一进程的心跳、扫描、SSH 登录和命令历史共享，TCP 连接成功后刷新。IPv4 和 IPv6 均规范化，回环、链路本地、组播及未指定地址不作为本机身份；仅回环连接或缺少可用地址时兼容旧来源识别。无需配置 agent_ip，旧 YAML 的该字段以及 ANQUAN_AGENT_IP 被忽略。仍无识别结果时 UDP ip 为空，接收 Master 使用数据报来源地址。机器主键仍是 IP，不同网络中地址相同的节点仍会碰撞。

主控以 `ip` 为机器主键，`host` 仅作为主机名展示。接收旧 Agent 的报文缺少 `ip` 时，使用 UDP 数据报来源 IP。UDP 来源端口是临时端口，不能当作机器标识。机器 IP 变化会形成新的机器记录。该协议用于内网传输，无需认证或加密；主控开通对应 Agent 机器访问 `55555/udp` 的网络即可。

## 公共信封

| 字段 | 类型 | 含义 |
|---|---|---|
| `version` | integer | 当前为 `1` |
| `event_id` | string | SHA-256 十六进制事件标识；持久化事件按 `(ip,event_id)` 唯一存储，心跳只更新机器状态 |
| `ip` | string | 被监控机器 IP；旧报文可回退 UDP 来源地址 |
| `host` | string | 被监控机器主机名 |
| `time` | RFC3339 string | 心跳为发送时间；告警/摘要为扫描开始时间；登录/操作命令为真实发生时间，带时区 |
| `type` | string | `heartbeat`、`scan_summary`、`alert`、`ssh_login`、`command_history` |
| `data` | object | 对应类型的数据 |
| `ack_requested` | boolean | 可选，默认 false；为 true 时 Master 成功提交后回复 ACK |

主控应另存 `received_at` 作为接收时间。按登录发生时间筛选时使用 `data.login_time`，避免首次补读、积压和延迟报文落入接收当天；机器在线状态应按接收时间更新。

## 自动上线、独立心跳与异常离线

配置 `server` 后，Agent 启动时在首轮采集前立即发送 `heartbeat`。`-service` 常驻模式随后每 30 秒发送一次，独立于默认 300 秒的扫描周期；文件、进程或登录采集耗时较长时仍继续发送心跳。心跳发送失败会写入日志，后续扫描和心跳继续运行。`server: []` 不发送网络数据。

```json
{
  "version": 1,
  "event_id": "f1ad30fd2b83903c056b17d0889cd58b02a6b465b26f9e32d680b4b8bc780009",
  "ip": "172.22.0.101",
  "host": "node-a",
  "time": "2026-10-03T10:00:00+08:00",
  "type": "heartbeat",
  "data": {
    "interval_seconds": 30,
    "state": "running",
    "version": "0.4.0"
  }
}
```

`data.interval_seconds` 是心跳周期，必须是 1–86400 的整数；当前 Agent 固定为 30。`state` 和 Agent 程序 `version` 是附加信息，程序版本可省略。它们与公共信封 `version: 1` 的协议版本分别表示不同含义。

Master 收到首条有效心跳或检测事件时，按机器 IP 自动创建记录；每条有效上报按主控接收时间更新 `last_seen`。支持心跳的机器离线阈值为 `max(心跳周期 × 3, 30)` 秒，因此当前 Agent 连续超过 90 秒没有任何有效上报时显示 `status: abnormal_offline`（异常离线）、`online: false`；再次收到有效上报立即恢复 `status: online`、`online: true`。列表、机器详情和概览使用同一规则，接口同时返回 `heartbeat_interval_seconds` 和 `offline_after_seconds`。

`heartbeat` 只更新机器状态，不写入 `events`，不增加告警/登录/事件数量，也不触发 webhook。乱序心跳不会把机器的心跳周期回退到旧值。完整单次巡检 `-scan` 仅在采集前发送一次启动心跳，退出后不再周期上报；v0.6.8 已安装路径无参和 `-ssh-report` 只请求一次登录上报，在线心跳由常驻服务负责。需要持续在线状态时使用 `-service`。外部 timer 两轮之间没有常驻 Agent 时，超过阈值会显示离线。

旧 Agent 仍可只发送 `scan_summary`：没有收到独立心跳的机器使用 `max(扫描周期 × 3, 120)` 秒作为离线阈值，默认扫描 300 秒对应 900 秒，避免正常巡检间隔被误判离线。收到新 Agent 的独立心跳后自动使用心跳阈值。

数据库初始化或打开旧库时，Master 自动迁移 SQLite schema 到 `PRAGMA user_version=10`。v2 增加机器心跳字段；v3 扩展事件类型及命令来源 ID 去重索引；v4 保存持续离线状态；v5 增加共享 YAML 模板；v6 增加按机器分配的加密配置、版本和应用确认状态；v7 保存安全组件数据；v8/v9 增加事件保留与降噪策略；v10 保存安装下载窗口时长及允许域名。迁移保留机器信息、事件 ID、处理状态/备注、管理员密码、登录会话、webhook 配置及通知队列的重试记录和 ID 高水位。数据库版本与协议 `version: 1` 相互独立；旧 Master 不支持迁移后的库，降级须恢复升级前的一致性备份。

## TCP 配置下发（55556）

Master 监听 `55556/tcp`。v0.6.4 新机器自动安装的 `agent.service` 固定连接 `172.22.0.27:55556`。前台/单次模式的地址来自 -master、ANQUAN_MASTER 或自动保存的连接信息，无本地配置且无连接地址时使用固定 IP 兜底，完全独立于 YAML 的 server。裸域名或 IP 默认使用 TCP 55556，可用 host:TCP端口调整。YAML 的 server 仅向全部地址发送 UDP 数据，也支持域名，裸域名或 IP 默认使用 UDP 55555；server: [] 只关闭 UDP，不影响接收配置。域名不在配置校验阶段解析，保存主机名供每次连接/发送时解析；填写 DNS 主机名，不接受 URL 或路径。

不要求本地 `config.age`：Agent 自动保存连接信息供后续无参数运行使用。连接文件为 `/usr/local/anquan/agent.connection.age`，通过内置配套 age 密钥加密主控地址和自动识别身份；旧 `agent.connection.json` 成功迁移后删除。默认主控 IP 172.22.0.27 编译进程序，不依赖 DNS 解析；前台运行保留参数或环境变量设置地址的能力。内置密钥无法防 root 或逆向提取。无有效平台缓存或本地配置时，`-service` 只连接、注册并保持 TCP 心跳，等待下发，不开启巡检/登录/命令采集；Master 离线时持续重连；使用自定义域名时，DNS 暂时不可用也会持续重连。收到有效配置并完成运行环境检查和密文缓存后才启用采集并 ACK。主控明确取消分配时，无本地配置的 Agent 恢复等待，配置通道继续运行。

Linux 新机器从上传目录无参数执行会完成安装并启动后台服务后退出。v0.6.8 已安装路径无参或 `-ssh-report` 向 root 常驻服务的 Unix socket 请求一次 SSH 上报，使用当前有效配置，不运行完整巡检或 TCP 同步。普通用户无需读取 0600 配置，但必须由服务验证 SSH 上下文和调用者身份；root 没有 `SSH_CONNECTION` 时允许最近真实认证快照。仅 socket 不可用时 root 可从有效平台缓存/本地配置直接上报；服务明确拒绝、配置未应用或找不到真实记录均返回错误，不编造登录时间。原完整单次流程使用 `-scan`，该流程才限时同步配置并采集一轮。

每帧是 UTF-8 JSON 加换行（NDJSON），最大 8 MiB，`version: 1`。JSON 字符串内的 age 密文换行使用 JSON 转义。第一帧：

```json
{"version":1,"type":"hello","ip":"172.22.0.27","reported_ip":"172.22.0.27","host":"node-a","agent_version":"0.7.0","download_relay":true}
```

本机模式省略 discover_ip（false），`ip` 与 `reported_ip` 必须是同一规范化本机 IP。旧 Master 已支持显式 hello.ip，因此不识别新增字段时仍按本机 IP 登记，并直接发送配置；新版 Master 识别 reported_ip 后先确认身份再发送最新分配：

```json
{"version":1,"type":"identity","ip":"172.22.0.27","download_token":"<当前配置连接的随机令牌>"}
```

Agent 在发送 hello 前先加密保存本机地址并更新共享身份。新版主控确认帧必须与 Agent 选定的本机地址一致；返回代理地址或其它不同值时断开连接，保留本机身份，避免污染 UDP。旧 Agent 的 discover_ip=true 流程保留：主控按实际连接来源回复 identity；新版 Agent 仅在无法取得可用本机地址时使用该回退。旧 Agent 经过普通中转时仍可能被识别为中转地址，必须升级 Agent 才能主动携带本机 IP。`download_relay` 是可选能力声明；支持下载的主控在 identity 附 `download_token`，令牌仅保存在内存，控制连接断开后失效。旧主控不返回该令牌时，配置协议继续兼容，但有 Master 的新版 Agent 不执行公网直连安装回退。

没有分配时，revision 和 ciphertext 同时为空：

```json
{"version":1,"type":"config","revision":"<密文完整字节的SHA-256十六进制>","ciphertext":"-----BEGIN AGE ENCRYPTED FILE-----\n..."}
```

Agent 先验证 revision、age 完整性和节点平台的 YAML 配置，再原子保存程序旁的 `config.master.age`。常驻模式等待当前扫描结束，停止旧心跳、SSH 和命令采集工作、切换到新配置并重启相应工作后才确认成功：

```json
{"version":1,"type":"ack","revision":"<当前版本>"}
```

失败返回同版本和非空 `error`，保留当前有效配置及缓存；Master 记录失败供页面显示。Agent 将回执错误按 UTF-8 边界截断到 4096 字节内，避免长包管理器输出导致整条失败回执被拒收，完整输出留在本机日志。未知或旧版本 ACK 不改变新分配状态。主控保存每台机器最近分配的密文、版本、下发和确认状态，重启或连接恢复时自动重发。下发 HTTP 成功只表示保存成功，节点生效以 ACK 为准。

Agent 每 30 秒发送 `{"version":1,"type":"ping"}`，主控回复 `{"version":1,"type":"pong"}`。有效 hello 和 ping 更新机器活动时间；连接异常后 Agent 自动重连。页面 `connected` 单独表示配置 TCP 连接，机器 `online` 仍按最近活动时间及既有超时阈值计算。

主控配置优先于可选本地 config.age，常驻或 `-scan` 启动先使用有效缓存，再限时同步；无缓存且无本地配置时常驻等待。v0.6.8 已安装路径无参仅请求执行上报，不同步 TCP 或执行完整巡检。下发 server 列表立即生效并替换 UDP 目标，TCP 配置地址及自动 IP 不由 YAML 控制。连接文件 version 3 保存 master、local_ip 和兼容回退 observed_ip；version 1/2 自动迁移，并忽略旧手工 agent_ip。重启仅恢复仍属于本机接口的 local_ip，observed_ip 仅留作兼容元数据，不恢复为机器身份。临时 UDP 路由身份不强制落盘，由 TCP 选取的本机 IP 持久化。服务账号需要程序目录的缓存写入权限。升级顺序为支持执行事件的 Master、Agent，再更新 Web 示例。升级后本机 IP 会成为新的机器记录；已有代理记录可能混合多个节点的历史，不自动迁移或删除，旧目标的配置需按真实机器重新确认下发。

此通道沿用内网机器 IP 信任方式，没有单独的节点认证或 TLS；age 密文用于配置加密，不构成 Master 身份认证。仅允许可信 Agent 网络访问 55556/TCP。既有 UDP、HTTP 与 Webhook 的传输行为保持原有协议。

## 安装下载转发（复用 TCP 55556）

原 hello 配置连接保持 NDJSON、保活和 ACK 不变。安装下载另开到同一主控地址的 TCP 连接，首帧使用以下类型分流；不在配置连接内传输安装包，也不新增 HTTP 包目录。

Agent 实际需要下载时，用 identity 的 `download_token` 请求会话：

```json
{"version":1,"type":"package_session","ip":"172.22.0.11","token":"<download_token>"}
```

主控验证当前配置连接、Agent IP、实际连接来源和令牌，并检查管理员已为该机器分配非空配置及管理下载窗口后返回短期会话令牌；仅 hello 自动登记机器不能取得下载权限：

```json
{"version":1,"type":"package_session","token":"<下载会话令牌>","expires_at":"2026-10-20T09:00:00Z"}
```

随后每个下载流使用独立连接，以下载会话令牌和目标域名端口开始：

```json
{"version":1,"type":"package_relay","ip":"172.22.0.11","token":"<下载会话令牌>","target":"archive.ubuntu.com:443"}
```

主控确认 `{"version":1,"type":"package_ready"}` 后，该连接切换为原始双向字节流，直至连接结束。Agent 安装期的临时 `127.0.0.1` HTTP 代理只接受 GET、HEAD、CONNECT：HTTP 请求及 HTTPS 隧道均通过此流到软件源，TLS 仍由 Agent 和目标源端到端校验；包管理器的签名校验及 Tetragon SHA256 校验保留。APT/DNF/YUM 的依赖解析继续在 Agent 节点执行。

安装结束关闭临时代理，并用独立连接请求撤销会话：

```json
{"version":1,"type":"package_close","ip":"172.22.0.11","token":"<下载会话令牌>"}
```

成功回复 `{"version":1,"type":"package_closed"}`。上述操作失败回复 `{"version":1,"type":"error","error":"<简短原因>"}` 后关闭连接。总开关关闭、总窗口或会话过期、原配置连接断开、分配配置版本变化时，主控撤销授权并终止活动下载；下载会话不能跨控制连接重连或配置版本复用。单会话目前最长 10 分钟，且不超过总窗口到期时间；超时需在允许窗口内重新下发重试。

当前限额为每 Agent 最多 8 个下载流、全局最多 32 个下载流及 128 个会话；每流每方向最多 512 MiB、每会话累计最多 2 GiB。DNS 解析限时 5 秒，连接源站限时 10 秒，下载空闲超时 60 秒，另受会话总时长限制。

主控只转发允许列表中域名的 80/443，拒绝 IP 字面量、私网/回环/链路本地及其他保留地址。DNS 解析结果逐项检查后，以验证过的公网 IP 建立连接，防止再次解析切换到内网。重定向或镜像选择产生的新目标同样需要在白名单内；仅内置 `*.ec2.archive.ubuntu.com` 支持通配，其他允许条目必须是完整域名。不会自动接受任意自定义软件源或通过环境代理绕过检查。限时令牌是现有可信内网连接上的下载授权，不构成新的节点身份认证或 TCP 通道加密。

管理接口沿用既有登录鉴权：

| 接口 | 请求与返回 |
|---|---|
| `GET /api/settings/package-downloads` | 返回 `enabled`、`expires_at`（RFC3339 或 null）、`window_minutes`、`allowed_hosts`、`active_sessions`、`active_connections`、`bytes_transferred`、`last_error` |
| `PUT /api/settings/package-downloads` | 必填 `enabled`，可选 `window_minutes`（1–60，默认 15）与 `allowed_hosts`；省略可选字段保留当前设置，返回同上状态 |

Web 提供 15/30/60 分钟窗口。下载默认关闭，主控重启后关闭；仅窗口时长和允许域名持久化，token、活动窗口及下载会话不持久化。修改设置会撤销旧会话。关闭的是下载授权，TCP 55556 配置监听继续运行。该通道是主控统一公网出口的流式转发，不提供完整离线缓存；Master 需能访问目标软件源。部署和 Linux 验收见 [主控部署](主控部署.md#agent-安装下载)。


## 扫描摘要

即使没有告警，每轮完成采集仍发送 `scan_summary`，用于保存扫描结果及兼容旧 Agent 的在线判断。

```json
{
  "version": 1,
  "event_id": "d2bc9b09cf51d1b16eeedbe9b79094a90fdf1f42b4dc9ab891fb1b00d2a8a0c2",
  "ip": "172.22.0.101",
  "host": "node-a",
  "time": "2026-10-02T10:00:00+08:00",
  "type": "scan_summary",
  "data": {
    "collection_success": true,
    "alerts": 0,
    "errors": 0,
    "files": 12,
    "processes": 48,
    "logins": 1,
    "login_pending": false,
    "interval_seconds": 300,
    "finished_at": "2026-10-02T10:00:01+08:00"
  }
}
```

这里的 `interval_seconds` 是 Agent 常驻服务完整文件/进程巡检周期，默认 300 秒；独立心跳为 30 秒。v0.6.8 trigger 服务扫描不自动采集登录，执行请求的记录单独上报；显式 poll 的 SSH 独立采集由 `login.poll_interval_ms` 控制，默认 1000 毫秒。两者的登录记录均不要求计入每次完整巡检摘要，不能仅凭 `logins=0` 判断没有 SSH 上报。`collection_success` 仅表示采集完成，异常文件或缺失进程也可以是有效检测结果；应同时查看 `alerts` 与 `errors`。主控接纳乱序的心跳、告警、登录报文，旧扫描摘要不会覆盖新的摘要或心跳周期。

## 文件等通用告警

```json
{
  "version": 1,
  "event_id": "a3baf0fc452fe7c85a754e4364122415b4f79ed7f0e3a0deeb90ef4f27b1d642",
  "ip": "172.22.0.101",
  "host": "node-a",
  "time": "2026-10-02T10:00:00+08:00",
  "type": "alert",
  "data": {
    "module": "files",
    "kind": "modified",
    "target": "/etc/ssh/sshd_config",
    "message": "file content changed",
    "before": "900150983cd24fb0d6963f7d28e17f72",
    "after": "d41d8cd98f00b204e9800998ecf8427e"
  }
}
```

`target` 是异常文件路径、搜索规则或进程命令。文件常见类型为 `added`、`modified`、`deleted`、`missing`、`not_found`；检查失败可为 `inspection_error` 或 `collection_error`。从 Agent v0.5.1 起，fils/dir/search 命中任意配置 MD5 即正常，未知 MD5 初始化时记录为该路径的基线，之后变成另一个未知值产生 `modified`，不再仅因未命中配置值产生 `md5_mismatch`。主控仍可接收旧版 Agent 的 `md5_mismatch`。`before` / `after` 可省略：修改保存前后 MD5，删除只有旧 MD5，新增只有新 MD5；旧版允许列表不匹配保存允许值与当前值。主控应保存原始 `data`，不要把其他模块的这两个字段强制解释为 MD5。

## SSH 登录上报：trigger 与 poll

v0.6.8 默认 `login.mode: trigger`。系统 sshrc、已安装路径无参执行或 `-ssh-report` 每次请求上报一条匹配的真实成功认证记录；重复执行同一会话会产生独立执行 ID。原有两行 ssh-init.sh 保持兼容，由 root 服务读取配置和日志；常驻完整扫描不再自动补发相同登录。`login.enabled: false` 或无有效配置时不接受上报。

trigger 沿用 `ssh_login` 及协议 `version: 1`，新增字段如下。`login_time` 与外层 `time` 保持真实认证时间，执行时间单独保存在 `invoked_at`：

| data 字段 | 含义 |
|---|---|
| `id` | 本次执行请求的随机 32 位十六进制 ID；同一请求重传保持不变，不同执行分别生成 |
| `trigger` | 执行上报为 `execution` |
| `source_record_id` | 原 journal 游标或来源记录 ID；相同认证的多次执行可以相同 |
| `invoked_at` | 本次请求的时间，RFC3339 |
| `executed_by` | 经服务校验的执行用户；与原认证用户分开保存 |
| `source_port` | 可获得时保存原 SSH 客户端端口，用于匹配连接 |

例如一次执行对应的 data：

```json
{"id":"253273fd94e641bc8f78386576e7bfe2","trigger":"execution","source_record_id":"journal-cursor","source_ip":"192.0.2.10","source_port":42000,"login_time":"2026-10-02T09:55:00+08:00","user":"ops","terminal":"N/A","method":"publickey","invoked_at":"2026-10-02T10:00:00+08:00","executed_by":"ops"}
```

显式设置 `login.mode: poll` 才保留 v0.6.7 的增量模式：按 `login.poll_interval_ms` 独立采集成功登录，不等待默认 300 秒完整巡检。范围为 100–60000 毫秒，省略时默认 1000；沿用已有加密 `.logins` 游标和稳定来源 ID，升级不用清除状态。poll 模式拒绝执行上报请求，避免两种来源同时发出同一次登录。poll 报文继续使用原字段：

```json
{
  "version": 1,
  "event_id": "54a826e65b3cb37f3d1079b1cdef4c89eed136944b4607235376d248fcb18281",
  "ip": "172.22.0.101",
  "host": "node-a",
  "time": "2026-10-02T09:55:00+08:00",
  "type": "ssh_login",
  "data": {
    "id": "journal-cursor-or-source-record-id",
    "source_ip": "192.0.2.10",
    "login_time": "2026-10-02T09:55:00+08:00",
    "user": "ops",
    "terminal": "N/A",
    "method": "publickey"
  }
}
```

`ip` 是被登录机器，`source_ip` 是登录来源，两者不可混用。来源没有终端时 `terminal` 为 `N/A`。生产默认读取 journal 成功认证记录，支持非交互 SSH；wtmp 只能覆盖操作系统写入的会话。

trigger 不读取或更新 `.logins`，不更新 Prom；每次本机 `ssh_execution_complete` 保存执行及原认证 ID、调用者身份和 UDP 发送结果。poll 有新增登录时，`ssh_poll_complete` 保存本页记录数和发送结果，逐条仍写 `ssh_login`；空闲不逐秒写日志，错误查看 `ssh_login_error`。生产使用可读 journal 并确认已应用有效配置及非空 `server`；没有真实匹配记录时失败。每秒仅描述 poll 的采集节奏，UDP 发送成功不保证 Master 入库和机器人最终送达。

配套 Master 将新入库的 `ssh_login` 与通知任务在同一事务提交，向全部已启用 webhook 发送登录通知。正文保留机器、主机名、用户、来源 IP、终端、认证方式、真实登录时间和事件 ID。trigger 必须按独立执行 ID 分别入库通知，不能因 `source_record_id` 相同合并两次执行；重复提交同一执行 ID 不重复入队。poll 保留相同来源记录的去重，数据库中已有历史记录不补发；补读/延迟上报的登录首次入库时仍通知。通知失败沿用持久重试，重启后继续发送。

## 操作命令及落库确认（v0.6.0）

```json
{
  "version": 1,
  "event_id": "c530bd810e792eec8fe41d4b307878d84691c9a6febea5c9864bd471f0115413",
  "ip": "172.22.0.101",
  "host": "node-a",
  "time": "2026-10-09T02:42:50+08:00",
  "type": "command_history",
  "ack_requested": true,
  "data": {
    "id": "stable-source-record-id",
    "command_time": "2026-10-09T02:42:50+08:00",
    "user": "root",
    "terminal": "/dev/pts/1",
    "command": "alias ll='ls -alF'",
    "path": "/var/log/history.log",
    "offset": 0
  }
}
```

来源文件从头补传，之后按字节位置读取追加记录。`id` 由持久化的日志代号和记录起始字节位置生成；相同文本、用户及时间的两次操作仍有不同 ID。Master 使用 `command_time` 作为事件发生时间，保存原始 `data`，并额外按 `(机器 IP, command id)` 去重，因此主机名改变后重试也不重复入库。机器 IP 改变会形成另一台机器。`GET /api/events?type=command_history` 支持现有机器、时间、关键字、状态及分页参数。正常命令事件不进入告警 webhook 队列。

当信封带 `ack_requested: true`，Master 在数据库事务成功提交后向报文来源地址回复：

```json
{"version":1,"type":"ack","event_id":"c530bd810e792eec8fe41d4b307878d84691c9a6febea5c9864bd471f0115413"}
```

重复事件也回复匹配原报文 `event_id` 的 ACK。格式/校验错误或落库失败不确认。Agent 每条最多等待 2 秒，未收到匹配确认则保留加密 `.commands` 中的待发批次，随后重试；重启仍使用相同 ID。每个配置的 Master 均确认后才清空该批次。此机制为至少一次传输、主控幂等入库；依赖保留 Agent 状态和 Master 数据库。网络须允许 UDP 请求及返回流量。

命令采集按单行日志解析；非法格式及无法容纳于 UDP 的记录以 `alert` 上报，`module: history`、`kind: parse_error`、`target: 来源日志`，描述包含字节位置，并同样请求 ACK。文件读取/状态错误写 Agent 本机 `history_error` 日志。读取采集不会清空或轮转源日志；v0.7.4 的本地受管命令入口仅向默认日志追加单行记录，不改变此 UDP 协议。

升级顺序为 Master、Web、Agent；旧 Master 不支持 `command_history` 或落库 ACK，新 Agent 会保留待发数据并持续等待，不会把发送成功当作落库成功。

## 重复、持久化与投递边界

同一报告构造相同的事件 ID，多个 UDP 副本按 `(ip,event_id)` 去重。trigger 登录使用机器 IP、主机名、事件类型与本次执行 `id` 生成标识；同一请求的重传保持相同，下一次执行有新的 ID，即使原认证 `source_record_id` 相同也分别保留。poll 使用来源记录 `id`，同一登录跨完整巡检或独立轮询重新读取保持相同标识；不同来源 ID 的两次登录即使用户/IP/时间完全相同也分别保留。没有来源 ID 的兼容记录按其原始时间和内容生成标识。告警与摘要按扫描时间和内容生成标识，持续缺失在下轮仍产生新记录；文件变化因本地发布失败而跨轮重新检测，也可能形成新的告警观察记录。

常规巡检告警、登录、摘要和心跳的 Agent → Master 传输没有 ACK 或持久重传。成功发送只表示本地网络栈接受，不代表主控已存储；网络丢包、主控停机或超大数据报可能导致缺记录。命令采集通道及下述安全组件通道采用落库确认及持久重试。Master → webhook 的告警及登录通知在入库后采用持久重试，重复事件不重复入队。

## 安全组件通道（v0.7.0）

沿用 version=1、UDP 55555 和上述事务提交 ACK，增加 `security_event`、`component_status`。不改变配置 TCP 55556、已有身份或端口。

`security_event.data` 包含 `id`、`source`、`kind`、`severity`、`message` 及可选 `path` / `details`。来源覆盖 auditd、可选 Tetragon、sudo、native_fim、ssh_auth、policies、task。auditd/Tetragon 的信封时间优先使用源记录时间。warning/error/critical 级别进入原持久 webhook 队列，普通观察事件不通知。

`component_status.data` 包含 `components`、`config_hash`、`inventory`、`queue`，可能包含 `initialization_error`。组件包含启用、安装、运行、状态、版本、错误、配置 hash、应用时间及策略检查；长明细会截断，`omitted_checks` / `details_truncated` 明确表示省略。Master 保存事件及最新快照，较旧补传不会覆盖较新快照。

Agent 先将每条数据加密持久化到安装目录 `state/security/outbox/`，为事件创建时的每个目标保留独立 ACK 进度。仅当全部目标确认才删除；重启后补传保持相同 ID，Master 幂等。队列容量受事件数量和 256 MiB 磁盘边界约束，满时日志来源游标不前进。

`source: sudo`、`kind: io_chunk` 使用专表，分片 `details` 为 `session_id`、`generation`、`file`、`offset`、`total_size`、`complete`、`content_base64`。同一会话文件共享 generation，每片最多 24 KiB，单文件最多 64 MiB；乱序及相同内容重传可接受，冲突重叠拒绝。它不重复进入普通事件或 webhook，完整文件通过鉴权接口下载。

配置仍在原加密 YAML 内新增可选 `security` 段。常驻服务校验及应用组件后才确认新修订；安装/reload 失败保留上次有效配置，状态报告错误。旧 YAML 省略该段时兼容。组件、预设、路径及限制见 [安全组件接入与配置手册](安全组件接入与配置手册.md)。
