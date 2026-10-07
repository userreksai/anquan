# Anqu 安全检测 Agent（v0.4.0）

Anqu 在 Linux 节点持续检查文件 MD5、文件增删和进程变化，并逐条记录成功的 SSH 登录。服务启动时记录当前时间，每轮输出当前主机的完整检测结果、告警、JSON 报告和一份带采集时间的 Prometheus 文件。运行日志按北京时间零点切换文件。

本目录是 [anquan Agent](https://github.com/userreksai/anquan)。Agent 通过可配置的 UDP 接口向 [Master 主控](https://github.com/userreksai/anquan-server-master) 上报，默认关闭联网。详细需求对应关系见 [需求与实现说明](docs/需求与实现说明.md)，字段约定见 [Agent / Master 协议](docs/agent-master-protocol.md)。

配套主控与 Vue 前端的安装、端口、默认登录和密码重置见 [安全中心主控部署](docs/主控部署.md)。

Agent、Master 和 Web 的整体架构、模块职责、数据流、存储及可靠性边界见 [架构设计](docs/架构设计.md)。

正式部署、服务运行、SQLite 离线查询、SSH 与 UDP 调试、HTTP API 以及全部现有测试命令见 [部署调试与测试命令手册](docs/部署调试与测试命令手册.md)。

Agent 使用外置 age 加密配置：构建时只嵌入解密私钥，不嵌入巡检 YAML。同一份二进制可以部署到多个节点，每个节点使用自己的 `config.age`，放在可执行文件所在目录（不是 Shell 当前工作目录）。配置更新不必重新编译；无参数单次运行每次启动重新读取，`-service` 常驻模式替换后重启生效。采集、SSH 登录游标和 UDP 上报逻辑不变。本机管理员仍可能从程序或内存恢复私钥和配置。

## 构建和快速验证

构建机需要 Go 1.25 或更新版本。首次构建会下载 age 和 YAML 依赖。

```sh
git clone https://github.com/userreksai/anquan.git
cd anquan
go test ./...
go vet ./...
go run ./cmd/anqu-build -output ./dist/anquan -goos linux -goarch amd64
# ARM64：将输出名和 -goarch 改为 anqu-linux-arm64 / arm64。
```

Agent 和 Master 代码内置一组固定配套密钥，构建不会重新生成密钥，页面不显示或要求输入密钥。在“管理设置 → Age 配置加密”编辑 YAML，点击加密并下载 `config.age`，与 Agent 一起部署即可。无需密钥文件、环境变量或公钥输入。生产管理页面应使用 HTTPS 传输明文输入。源码中的固定私钥可被源码持有者或节点管理员提取，这个方案用于隐藏配置明文，不防上述人员解密。

构建不需要 YAML。可选 `-config ./config.yaml` 仅用于同时生成初始 `config.age`，不会将 YAML 编译进二进制。其他参数包括 `-output`、`-goos`、`-goarch` 和 `-go`；默认目标系统为 Linux。普通 `go build ./cmd/anqu` 也使用同一内置密钥。首次切换到此固定密钥版本时，需要更新 Agent 和 Master，并用新页面重新加密旧配置；之后配置更新无需编译。

部署后的目录例如：

```text
/usr/local/anquan/
  anquan
  config.age
```

保留密文完整的 `-----BEGIN AGE ENCRYPTED FILE-----` / `-----END AGE ENCRYPTED FILE-----` 标记。替换时先上传临时文件，再在同一文件系统重命名为 `config.age`，避免运行期间读到一半文件。明文、缺失、截断或公钥不匹配的配置会被拒绝，不回退到旧的内嵌配置。单次运行保持静默，失败退出码为 1；常驻模式会输出错误到服务日志。

本地演示使用相对路径、JSONL 模拟登录及独立输出目录，不需要系统日志或进程权限：

```sh
go run ./cmd/anqu-build -config ./demo/config.yaml -output ./demo/anqu -goos linux -goarch amd64
./demo/anqu
# 修改 demo/watched/app.conf 后再执行，查看 modified；第三次无修改则恢复 unchanged。
```

Windows 开发演示可使用 `-goos windows -output ./demo/anqu.exe`。生产进程监控依赖 Linux `/proc`。演示登录记录是固定测试数据，JSONL 首轮读取其中尚未记录的条目。

## 配置格式

完整中文模板见 [config.example.yaml](configs/config.example.yaml)。字段区分大小写：`FilesMonitoring`、`ProcessMonitoring`、`Process`、`fils` 均按以下拼写。每条路径/命令规则是一个 YAML 字符串；使用空格缩进。未知字段、非法 MD5、重复规则及多个 YAML 文档会被拒绝。

```yaml
output_dir: /usr/local/anqu
state_file: state/md5.json
timezone: Asia/Shanghai

FilesMonitoring:
  fils:
    - /etc/ssh/sshd_config|/etc/ssh/ssh_config
    - /etc/ssh/sshrc
    - /etc/hosts.allow
  dir:
    - /etc/cron.d/
  search:
    - authorized_keys,/root|/home|/var
    - id_rsa,/root|/home|/var

ProcessMonitoring:
  exists:
    # 按目标节点实际完整命令调整；默认仅检查关键进程存活。
    - '/usr/sbin/sshd -D'
  # 省略 Process，关闭全机进程增删和实例数量变化告警。

login:
  enabled: true
  source: journal
  journal_command: journalctl
  initial_lookback_hours: 24
  timeout_seconds: 10
  max_records: 1000

server: []
# Master 接收端就绪后替换为：
# server:
#   - 172.22.0.100:55555

setup:
  logs: /var/log/时间anquan.log
  prom: /var/lib/node_exporter/textfile_collector/时间process_monitor.prom
  interval_seconds: 300
```

这是路径示例。不同发行版可能没有 `sshrc`、`hosts.allow` 等文件：保留它们表示必须检查，缺失会告警；其他可正常读取的文件仍建立基线，缺失路径后来出现时报告新增。不需要检查时从配置移除。不存在的搜索根目录同样记录，没有匹配文件时记录 `not_found`。

`FilesMonitoring` 或 `ProcessMonitoring` 整段省略可关闭对应模块；`login.enabled: false` 关闭登录采集。新格式自动关闭旧 `md5`、`existence` 默认模块，旧格式仍兼容。不要用空的顶层监控段代替省略。

相对路径以节点可执行程序所在目录为基准，`state_file` 相对于 `output_dir`。路径不展开 shell 变量、`~` 或通配符。`server` 接受 IP 和端口，IPv6 写作 `[2001:db8::1]:55555`。`interval_seconds` 默认 300，范围 1–86400，仅用于 `-service` 模式。

### 文件规则和多对多 MD5

| 配置 | 检测范围 |
|---|---|
| `fils: [路径1\|路径2[,MD5...]]` | 每个给定文件；路径是目录时递归处理目录内普通文件 |
| `dir: [目录1\|目录2[,MD5...]]` | 递归处理目录内所有普通文件 |
| `search: [文件名,目录1\|目录2[,MD5...]]` | 在所有根目录递归搜索精确文件名，比较每个找到的文件 |

不提供 MD5 时，首次完整扫描记录初始 MD5，不把既有文件当成新增。以后比较上一次成功扫描，记录 `added`、`modified`、`deleted`，并在报告和日志落盘后更新基线。因此一次修改会在发现的那一轮告警；随后内容不变则为 `unchanged`。

提供 MD5 时，后面的所有值组成同一规则的允许集合，每个文件都必须匹配其中任意一个值。不会按位置把路径和 MD5 配对，也不要求每个允许值都用到。例如以下两个文件允许三个内容版本：

```yaml
FilesMonitoring:
  fils:
    - /opt/app/a.conf|/opt/app/b.conf,d41d8cd98f00b204e9800998ecf8427e,900150983cd24fb0d6963f7d28e17f72,5d41402abc4b2a76b9719d911017c592
```

以上哈希是格式演示，部署时用实际 `md5sum` 结果替换。MD5 必须是 32 位十六进制，不能填写 `md51`。两个文件分别命中任意允许值才正常；只有一个命中时，日志同时保留正常文件、异常文件的当前 MD5、允许值和规则命中统计，并为异常文件产生 `md5_mismatch`。两个文件内容相同、都匹配同一个允许值，也属于正常。

固定允许集合不会被自动学习覆盖；不匹配会在每轮重复告警。即使配置固定 MD5，目录成员的新增和删除仍与上轮清单比较并产生告警。配置路径缺失产生 `missing`，搜索无结果产生 `not_found`。扫描权限不足、读取失败或文件在计算期间变化会使模块失败，保留旧基线，避免把扫描不完整误判为删除。

文件重命名记为删除加新增。只改变属主/权限/时间戳不会构成内容变化。符号链接和特殊文件不计算 MD5，不进入目录链接；已跟踪文件被替换成链接/特殊文件时显式报错。Agent 自己的输出、日志和状态路径自动排除。MD5 用于本次要求的内容比较，不承担数字签名或防碰撞证明。

### 进程规则

推荐生产配置仅保留 `exists`，按节点职责逐行列出必须运行的服务，并省略整个 `Process` 段。示例中的 sshd 命令必须按目标节点实际值调整；`ssh` 是客户端，不能作为 `sshd` 服务的备选命令。

`exists` 每行是一个独立必须满足的规则，`|` 分隔多个系统适配命令，任意一个运行即满足该行。允许两个以上备选。命令经空白归一化后整行精确比较，`/usr/sbin/sshd -D-extra` 不会匹配 `/usr/sbin/sshd -D`。请按目标主机 `/proc/<PID>/cmdline` 的实际命令填写；仅文件存在不等于进程正在运行。

`Process: {}` 开启整个进程列表的滚动监控。首次建立列表；之后比较完整命令和实例数量，因此相同命令由两个实例变一个也会报告 `deleted`。白名单保留在当前清单和日志中，只抑制列表增删告警，仍参与 `exists` 检查。省略 `Process` 时只检查 `exists`。

全机模式会将临时命令、SSH 会话和内核线程的变化纳入比较，可能一次产生大量告警。`whitelist` 只支持完整命令精确匹配，不支持通配符、前缀或正则；清空白名单或改成 `Process: {}` 不会缩小范围。当前没有仅监控指定业务进程变化的 include 配置。

已有节点降噪时，在实际 YAML 中删除 `ProcessMonitoring.Process`，保留并核对 `exists`，然后重新加密并替换 `config.age`，常驻服务需重启。此模式不读取或更新 `.processes` 基线，无需删除旧基线，也不要清理文件基线或登录游标。以后重新启用全机监控时，应先停止 Agent，备份并移走旧 `.processes`，避免将停用期间的变化一起告警。

此调整关闭全机变化告警，但本地报告和日志仍保存完整进程清单；关键进程持续缺失时仍每轮告警，当前没有持续缺失告警的冷却配置。验收时检查新扫描中 `processes.changes` 为空，存活检查正常；历史告警及主控已入队的通知不会因配置变更自动清除。

读取 `/proc` 不调用 shell 或 `ps`，排除当前 Agent 的 PID。没有 argv 的内核线程或僵尸进程以 `[comm]` 记录。扫描时进程正常退出会跳过；权限或读取错误使本轮进程模块失败并保留基线。

## 每次成功 SSH 登录

新模式默认 `login.source: journal`，通过 `journalctl` 读取 sshd/sshd-session 的成功认证事件，记录每个事件的时间、用户、来源 IP、认证方式及可获得的终端。SSH 非交互命令同样可以从成功认证日志取得记录。认证行通常没有终端，此时明确记为 `N/A`，不猜测终端。

首次从 `initial_lookback_hours` 指定的窗口开始，默认 24 小时；之后持久化 journal 游标。`max_records` 默认 1000，是每轮处理日志事件的页上限，不是只保留最后 1000 次登录；有积压时 `pending` 为真，后续轮次从下一事件继续。登录列表逐条写入 `ssh_login` 日志、JSON 和可选 UDP；`login.record` 同时保留最近一次登录。

| 数据源 | 配置和边界 |
|---|---|
| `journal` | 需要可用的 `journalctl` 和读系统日志权限；日志保留周期必须覆盖 Agent 停机时间 |
| `authlog` | `path: /var/log/auth.log` 或 `/var/log/secure`；解析 sshd 成功认证行，支持 RFC3339 或传统 syslog 时间 |
| `jsonl` | 自定义每行一个成功登录对象；按记录去重并分页，首次读取文件内全部尚未记录的条目 |
| `wtmp` | `path: /var/log/wtmp`、`last_command: last`；需要支持 `--time-format iso` 的 util-linux last；只覆盖系统实际写入 wtmp 的会话 |

`authlog` 保存文件前缀和字节偏移，并尝试从保留的未压缩 `path.*` 轮转文件续读；不读取 `.gz`、`.xz`、`.bz2`。初次只读取当前日志，丢失、截断或压缩掉续读所需文件会报错，不能保证补回已删除的事件。传统 syslog 没有年份和时区，按目标节点本地时区解释并处理跨年。`wtmp` 没有记录的非交互 SSH 无法靠它恢复，因此需要逐次 SSH 记录时使用 journal 或完整 authlog。

JSONL 示例：

```json
{"source_ip":"192.0.2.10","login_time":"2026-10-02T10:00:00+08:00","user":"ops","terminal":"pts/0"}
```

时间必须包含时区，终端未知填 `N/A`；可额外提供稳定 `id` 和 `method`。格式错误或源读取失败时，不推进登录状态。切换登录源应先备份对应 `.logins` 状态，防止错用原游标。

## 日志、报告和 Prometheus

服务启动立即输出包含当前北京时间、主机名的启动记录；每轮有 `scan_started`、各模块完整结果、独立 `alert` / `ssh_login` 事件和 `scan_complete`。正常结果也写入日志，包含文件实际 MD5、规则匹配情况和进程清单。停止服务时记录停止事件。日志同时写标准输出和每日 JSONL 文件，systemd 可从 journal 查看。

默认或模板配置输出：

| 路径 | 内容 |
|---|---|
| `/var/log/20261002anquan.log` | 北京时间当天的 JSONL 日志，零点自动换文件 |
| `/usr/local/anqu/20261002_100000.123456789+0800.json` | 单轮完整检测报告 |
| `/var/lib/node_exporter/textfile_collector/20261002_100000.123456789+0800process_monitor.prom` | 单轮指标快照；每次执行都会生成新文件 |
| `/usr/local/anqu/textfile/anqu.prom` | 固定文件名的最新状态指标 |
| `/usr/local/anqu/state/md5.json.files` | 文件 MD5 和成员清单滚动基线 |
| `/usr/local/anqu/state/md5.json.processes` | 进程列表滚动基线 |
| `/usr/local/anqu/state/md5.json.logins` | 登录游标及已记录状态 |

`setup.logs` 中的 `时间` 或 `{date}` 替换为北京时间 `YYYYMMDD`，禁止 `{time}`，始终按北京时间日切。`setup.prom` 的 `时间` / `{time}` 替换为含纳秒的采集时间；即使仅写 `{date}` 也自动补足本轮时间，避免覆盖。没有占位符时自动添加日期或采集时间前缀。占位符只允许出现在文件名；配置目录时会补默认文件名。`timezone` 可控制报告显示，但不改变日志零点切割规则。

每轮快照使用 `anqu_snapshot_` 指标前缀，并给每条样本增加 `host` 和 `run_id` 标签，因此同一 textfile 目录保留多轮快照不会产生相同标签集合的重复样本。最新状态继续使用 `anqu_` 前缀。生产告警通常查询最新状态：

```text
--collector.textfile.directory=/usr/local/anqu/textfile
```

若要采集所有历史快照，则让 node_exporter 读取 `setup.prom` 所在目录。每轮都会增加时间序列，历史文件没有自动清理，需要明确保留期限。可将 `setup.prom` 设为 `/usr/local/anqu/textfile/时间process_monitor.prom`，使同一目录同时采集最新状态和快照；两种前缀互不冲突。不要把旧版本中没有 `run_id` 的历史 `.prom` 混入此目录。

常用最新状态指标：

| 指标 | 含义 |
|---|---|
| `anqu_collection_success` / `anqu_collection_errors` | 本轮采集状态和错误数量 |
| `anqu_run_timestamp_seconds` | 最近一轮完成时间 |
| `anqu_module_enabled{module}` / `anqu_module_success{module}` | 各模块开启和成功状态 |
| `anqu_alerts` | 本轮告警总数 |
| `anqu_files_check{path,rule,mode,status}` | 各文件校验状态 |
| `anqu_files_change{path,kind}` | 本轮文件增删改 |
| `anqu_process_exists{rule}` | 某组备选命令是否至少有一个运行 |
| `anqu_process_instances{command,whitelisted}` | 完整命令对应实例数量 |
| `anqu_ssh_logins_new` / `anqu_ssh_logins_pending` | 本轮新增登录数和积压标记 |
| `anqu_last_login_info` / `anqu_last_login_timestamp_seconds` | 最近登录信息和时间 |

`collection_success: true` 表示完成采集，不表示没有异常；MD5 不匹配或进程缺失属于有效检测结果。查看报告中的 `alerts` 和模块明细。失败模块保留错误状态，避免将失败当成健康。报告默认权限 0640，基线 0600，指标 0644，日志 0640。

## UDP 主控接口

`server: []` 不联网，所有检测和通知结果保存在本地。填写 IP:端口后，Agent 启动时在首轮采集前立即向每个地址发送 `heartbeat`，`-service` 常驻运行期间每 30 秒独立上报心跳，耗时扫描不阻塞心跳。每轮采集完成后发送一个 `scan_summary`，以及逐条 `alert`、`ssh_login` JSON 数据报：

```json
{"version":1,"event_id":"唯一事件摘要","ip":"172.22.0.101","host":"node-a","time":"2026-10-02T10:00:00+08:00","type":"alert","data":{"module":"files","kind":"missing","target":"/etc/ssh/sshrc","message":"configured file or directory does not exist"}}
```

主控 UDP 默认端口为 `55555`，使用内网通信，无需认证或加密，开通相应 Agent 到主控的网络即可。`ip` 默认取连接当前主控时的本地出口地址；可增加顶层 `agent_ip: 172.22.0.101` 固定机器主键，适用于 NAT、多网卡或多个主控路径不同的情况。不同机器必须配置不同的 IP。主控收到首次上报即自动创建机器；连续超过 90 秒没有有效上报时显示“异常离线”，再次上报立即恢复“在线”。心跳只更新机器状态，不进入事件历史，不触发 webhook。旧 Agent 没有独立心跳时，仍按扫描周期的三倍（最低 120 秒）判断离线，默认 300 秒扫描对应 900 秒。

每轮 `scan_summary` 包含巡检间隔 `interval_seconds`，与心跳的 30 秒周期分别保存。文件告警的 `target` 是文件路径或搜索规则，`before` / `after` 保留前后 MD5；成功登录事件保留来源 `source_ip`、实际 `login_time` 和稳定 `id`，外层 `time` 同样使用登录发生时间。

同一报文重复提交保持 `event_id`；具有稳定来源 ID 的登录跨扫描重读也保持事件 ID，主控可以按机器 IP 与事件 ID 去重。持续缺失等告警在不同扫描轮次分别记录。发送统计、实际上报的机器 IP 和错误写入本轮报告及日志。UDP 为尽力发送，发送成功只代表本机交给网络栈，没有主控确认或重传队列；完整信息仍以本地报告为准。完整 JSON 示例、兼容旧版的接收规则和投递边界见 [协议文档](docs/agent-master-protocol.md)。

## 运行和 systemd 部署

节点只需对应架构的 Agent，不需 Go 或 YAML。假定构建产物和部署单元已传到当前目录：

```sh
sudo install -d -m 0755 /usr/local/anqu
sudo install -m 0700 ./anqu-linux-amd64 /usr/local/anqu/anqu
sudo install -m 0600 ./config.age /usr/local/anqu/config.age
sudo /usr/local/anqu/anqu
# 退出码 2 表示检测到告警；不等于程序未执行。
```

无参数默认静默执行一轮（不输出到终端，本地日志、上报和退出码保留），并在采集前发送一次启动心跳。`-service` 启动常驻循环，启动心跳发送后立即执行首轮采集，并按 `setup.interval_seconds` 周期执行，不重叠执行；单轮超过周期时跳过无法及时执行的节拍。常驻模式另有独立的 30 秒心跳，不受扫描周期或耗时影响。`-help`、`-version` 用于查看帮助和版本；没有节点 `-config`、`-check-config` 或导出配置接口。

推荐常驻服务：

```sh
# 从旧 timer 升级时先停止它；已有配置和基线应保留备份。
sudo systemctl disable --now anqu.timer 2>/dev/null || true
sudo systemctl stop anqu.service 2>/dev/null || true
sudo install -m 0644 deploy/anqu.service /etc/systemd/system/anqu.service
sudo systemctl daemon-reload
sudo systemctl enable --now anqu.service
sudo systemctl status anqu.service
sudo journalctl -u anqu.service -n 50 --no-pager
```

服务单元使用 `Type=simple`、`Restart=on-failure`、`RestartSec=5`。常驻服务记录单轮错误并继续后续巡检；正常停止使用 `systemctl stop anqu.service`。

如使用外部调度，改用附带的可选 oneshot/timer，不同时启用常驻服务：

```sh
sudo systemctl disable --now anqu.service
sudo install -m 0644 deploy/anqu-oneshot.service /etc/systemd/system/anqu-oneshot.service
sudo install -m 0644 deploy/anqu.timer /etc/systemd/system/anqu.timer
sudo systemctl daemon-reload
sudo systemctl enable --now anqu.timer
sudo systemctl start anqu-oneshot.service
```

timer 在开机一分钟后启动，每次任务结束五分钟后再运行。其周期由 timer 决定，不读取 `interval_seconds`。oneshot 的 `SuccessExitStatus=2` 接受正常发现告警的退出状态。单次运行结束后不再发送心跳，主控会在超过 90 秒没有上报时显示异常离线；需要持续自动在线状态时使用上面的常驻服务。

| 单次退出码 | 含义 |
|---|---|
| `0` | 完成采集且没有告警；初次完整建基线也可为 0 |
| `1` | 参数、配置、采集、输出、状态保存或通知发送出现错误 |
| `2` | 完成采集并发现文件/进程等告警 |

## 基线、升级和验证

文件/进程基线和登录游标只在结果报告及详细日志成功落盘后提交。不完整扫描保留旧状态；一个模块失败不阻止其他成功模块产出结果。多个输出文件和状态不是同一事务，崩溃可能导致下轮重复记录，优先避免未记录就消费变化。

文件监控范围、固定 MD5 集合或输出/状态位置变更后，旧 `.files` 基线会拒绝复用；进程白名单变更后 `.processes` 也需重建；切换登录源需处理 `.logins`。升级程序时先停止服务，备份相应状态文件后再建立新基线。只移动需要重建的状态，避免丢失其他模块历史，例如：

```sh
sudo systemctl stop anqu.service
sudo cp -a /usr/local/anqu/state /usr/local/anqu/state.backup-$(date +%Y%m%d%H%M%S)
# 仅在修改文件监控规则、需要明确重建时执行：
sudo mv /usr/local/anqu/state/md5.json.files /usr/local/anqu/state/md5.json.files.previous
sudo install -m 0700 ./anqu-linux-amd64 /usr/local/anqu/anqu
sudo systemctl start anqu.service
```

旧 `md5` / `existence` 配置可以继续运行；新模块使用独立后缀，不自动把旧 MD5 状态视为新规则的可信基线。停止原 timer 后迁移到常驻服务，避免重复调度。A 上保存私有 YAML，节点无需留存旧明文配置。

验收时先运行 `go test ./...`、`go vet ./...`，再在目标 Linux 主机验证：首次基线、文件增删改、多 MD5 部分匹配、进程 OR 规则和实例变化、白名单、连续多次 SSH 登录、服务重启续读、北京时间零点切割、每轮新 `.prom` 与 node_exporter 采集。仓库的自动测试使用隔离目录和模拟日志；不能替代目标机的 journal 权限、`/proc` 可见性、systemd 和网络接收端验收。

服务按周期采样，无法发现两次巡检之间发生又恢复的短暂文件/进程变化。日志数据源已丢弃的登录记录不能凭空恢复。历史报告、日志和指标不自动清理，由部署方按保留期限归档。当前源码文档不代表已有 `dist` 或旧发布压缩包已同步更新，交付前应重新构建。
