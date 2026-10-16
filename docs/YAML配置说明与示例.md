# Anqu YAML 配置说明与完整示例

本文说明 v0.6.6 起提供、v0.7.0 继续兼容的基础配置，以及配套 Master 和 Web。这里的 YAML 控制目标 Linux 节点检查哪些文件、哪些进程、怎样采集成功 SSH 登录和操作命令，以及把结果保存在哪里、发给哪台主控。v0.7.0 新增的 `security` 组件配置另见[安全组件接入与配置手册](安全组件接入与配置手册.md)。

可以先复制[中文注释版配置](../configs/config.annotated.yaml)，按本文调整，再通过管理页面下发。想快速理解配置后的效果，先看第 3 节；实际操作按第 11 节完成；第 12 节用于确认结果。

## 1 先认识配置会产生什么效果

| 你想实现的事情 | 应配置的位置 | 生效后的行为 |
|---|---|---|
| 检查某个配置文件有没有变化 | `FilesMonitoring.fils` | 首轮记录内容摘要，后续扫描发现内容变化时产生告警 |
| 检查某个目录里的文件增删改 | `FilesMonitoring.dir` | 递归比较普通文件清单和内容，分别记录新增、删除和修改 |
| 找出多个目录里的同名文件并检查 | `FilesMonitoring.search` | 按精确文件名递归搜索，对每个匹配文件分别检查 |
| 检查关键服务有没有运行 | `ProcessMonitoring.exists` | 每轮检查完整进程命令；必须进程不存在时告警 |
| 检查全机进程及实例数量变化 | `ProcessMonitoring.Process` | 首轮建立清单，后续比较完整命令和对应实例数量 |
| 记录成功 SSH 登录 | `login` | 增量读取认证日志，记录用户、来源 IP、发生时间等 |
| 上传已经写入操作日志的命令 | `history` | 首次分批补传，之后独立读取新增命令并等待主控入库确认 |
| 把结果发给平台 | `server` | 使用 UDP 向列表内的全部接收主控上报 |
| 调整巡检频率 | `setup.interval_seconds` | 常驻服务按指定秒数执行文件、进程和登录巡检 |
| 指定日志和指标位置 | `setup.logs`、`setup.prom` | 追加当天日志，并覆盖固定的 Prometheus 指标文件 |

文件的 MD5 可以理解成根据文件内容计算出来的“内容摘要”。“基线”是上一次成功扫描保存的文件内容摘要和清单，程序用它与本轮结果比较。“游标”是登录或命令日志已经读到的位置，用来接着读取而不重复从头开始。

这个 Agent 检测和记录异常。配置文件监控不会自动阻止文件被修改，进程监控不会自动拉起服务，SSH 登录采集不会阻止登录，操作命令采集不会自动拦截命令。

## 2 YAML 怎样写才正确

### 2.1 缩进代表归属关系

```yaml
FilesMonitoring:
  fils:
    - '/etc/ssh/sshd_config'
    - '/etc/ssh/ssh_config'
```

这表示 `FilesMonitoring` 下面有一个叫 `fils` 的列表，列表里有两个文件。第二条规则要放在同一个 `fils` 下方，不能重新添加另一个顶层 `FilesMonitoring`。

使用空格缩进，建议每层两个空格；不要用 Tab。冒号后面的空格用于分隔字段和值，`- ` 表示列表的一项，`#` 后面是注释。注释只是说明，不会执行；取消注释后，对应配置才参与解析。

### 2.2 字段名必须按原样写

| 正确字段 | 容易写错的形式 | 后果 |
|---|---|---|
| `FilesMonitoring` | `filesMonitoring`、`files_monitoring` | 未知字段，拒绝配置 |
| `fils` | `files` | 未知字段，拒绝配置 |
| `ProcessMonitoring` | `processMonitoring` | 未知字段，拒绝配置 |
| `Process` | `process` | 未知字段，拒绝配置 |
| `interval_seconds` | `interval` | 未知字段，拒绝配置 |

`fils` 是现有程序定义的拼写，应原样使用。开关用 `true` 或 `false`，数值按单位填写。例如 `300` 秒是 5 分钟，不能填 `5m`。

路径和命令建议放在单引号里。含冒号、`#`、反斜杠的字符串尤其需要注意引用。单引号字符串中如果要写一个单引号，需写成两个连续单引号。YAML 引号只保证字符串正确解析，不会让程序停止把 `|`、`,` 当作规则分隔符。

本程序只接受一个 YAML 文档，不支持把多份配置用 `---` 连在一起；也不接受用纯 JSON 对象替代 YAML 配置。下文标为“配置片段”的内容，需要替换或合并到现有同名段，不能全部直接拼接到文件末尾。

## 3 一份可以照着改的完整配置

以下是完整的新格式示例。文件路径和进程命令属于被监控的目标机器，需要按实际情况修改。`server: []` 表示先只保存本地结果；需要平台接收数据时，按注释替换。

```yaml
# Agent 保存状态和辅助指标的位置。
output_dir: /usr/local/anquan
state_file: state/md5.json
timezone: Asia/Shanghai

FilesMonitoring:
  fils:
    # 两个文件都检查。
    - '/etc/ssh/sshd_config|/etc/ssh/ssh_config'
  dir:
    # 递归检查这个目录里的普通文件。
    - '/etc/cron.d/'
  search:
    # 搜索所有恰好叫 authorized_keys 的普通文件。
    - 'authorized_keys,/root|/home'

ProcessMonitoring:
  exists:
    # 替换为本机 /proc/<PID>/cmdline 的实际完整命令。
    - '/usr/sbin/sshd -D'
  # 省略 Process，只检查必须进程是否运行。

login:
  enabled: true
  source: journal
  journal_command: journalctl
  initial_lookback_hours: 24
  timeout_seconds: 10
  max_records: 1000

history:
  enabled: false
  path: /var/log/history.log
  timezone: Local
  poll_interval_ms: 1000
  max_records: 100

# 想上报到主控时，将这一行替换成下面的列表。
server: []
# server:
#   - '172.22.0.27:55555'

setup:
  logs: '/var/log/时间anquan.log'
  prom: /var/lib/node_exporter/textfile_collector/process_monitor.prom
  interval_seconds: 300
```

配置应用后，常驻 Agent 在取得有效配置后先巡检一轮，之后每 300 秒巡检。若正在启动时与配置主控同步，首次巡检可能先等待约 3 秒；没有有效配置时会等待下发，不执行采集。

这份示例会检查两个 SSH 配置文件、`/etc/cron.d/` 中的普通文件以及搜索出的 `authorized_keys`，检查 sshd 是否运行，并采集成功 SSH 登录。它没有开启全机进程变化告警，也没有开启操作命令采集。

第一次扫描会记录已经存在的被跟踪文件作为基线，通常不会把它们报告为新增。这份示例的进程部分只做 exists 检查；添加 Process 后才会建立全机进程比较基线。但必需路径不存在、搜索没有结果、必须进程不匹配，第一轮就会告警；首次回看范围内的成功 SSH 登录也会形成新记录。

**照抄前至少检查三件事：**文件路径是否存在且需要检查、sshd 的实际完整命令是什么、是否需要将 `server` 改成接收主控。找不到 `authorized_keys` 时会产生 `not_found`；不要求这个文件必须存在的机器，应删除整个 `search` 子段。

## 4 数据目录和时间字段

### 4.1 基础字段的默认值

| 字段 | 默认值 | 怎样配置 | 生效后的效果 |
|---|---|---|---|
| `output_dir` | `/usr/local/anquan` | 可写的数据目录；可用绝对或相对路径 | 保存状态目录和 `textfile/anqu.prom` 等输出 |
| `state_file` | `state/md5.json` | 状态文件的基础路径；相对路径以 `output_dir` 为基准 | 新模块在此路径后追加各自后缀保存状态 |
| `timezone` | `Asia/Shanghai` | 合法时区，如 `Asia/Shanghai`、`Asia/Bangkok`、`UTC` | 控制巡检结果中的时间表示，不修改系统时区 |

当 `output_dir: /usr/local/anquan`、`state_file: state/md5.json` 时，主要文件位置如下：

```text
/usr/local/anquan/state/md5.json.files       文件基线
/usr/local/anquan/state/md5.json.processes   全机进程对比基线
/usr/local/anquan/state/md5.json.logins      成功登录读取游标
/usr/local/anquan/state/md5.json.commands    操作命令读取游标和待发送批次
/usr/local/anquan/textfile/anqu.prom         最近一次巡检的稳定名称指标
```

这些文件在相应模块使用时产生。`.processes` 用于开启 `Process` 后的进程对比；只配置 `exists` 不需要这个对比基线。基础 `md5.json` 本身用于兼容旧 `md5` 模块。状态内容经过加密，不能因为文件名含 `.json` 就当作明文 JSON 手工编辑。

程序会创建所需输出目录，但运行用户必须有权限。监控目标不会因为写入 YAML 就自动创建。

### 4.2 相对路径究竟相对于哪里

假设 Agent 程序在 `/usr/local/anquan/anquan`：

| 配置值 | 实际路径 |
|---|---|
| `output_dir: data` | `/usr/local/anquan/data` |
| 上述情况下 `state_file: state/md5.json` | `/usr/local/anquan/data/state/md5.json` |
| 文件规则中的 `watched/app.conf` | `/usr/local/anquan/watched/app.conf` |
| `setup.logs: logs/时间anquan.log` | `/usr/local/anquan/logs/20261014anquan.log`，日期按北京时间 |
| `history.path: logs/history.log` | `/usr/local/anquan/logs/history.log` |

文件规则、日志、指标、登录源和命令日志里的相对路径，通常都以 **Agent 可执行程序所在目录** 为基准，不以 Shell 当前目录或 `output_dir` 为基准。`state_file` 是上述例外；旧 `existence.files` 的相对路径则使用其 `base_dir`。

不要填 `~/app`、`$HOME/app`、`${APP_DIR}/config` 或 `/opt/app/*.conf` 来期待展开。程序不会展开 Shell 变量、用户目录缩写或通配符。

### 4.3 三种时间设置不要混淆

| 设置 | 控制对象 |
|---|---|
| 顶层 `timezone` | 巡检结果及部分记录中的时间表示 |
| `history.timezone` | 解释命令源日志中没有时区的日期时间 |
| 日常 Agent 日志 | 外层时间和日志文件日期固定使用北京时间 UTC+8 |

例如顶层设置 `Asia/Bangkok` 后，Agent 日志仍按北京时间零点换文件，不会改成泰国时间零点。Web 的显示时间还由页面使用的时区规则决定；命令页面按浏览器时区展示，事件实际发生时间和接收时间是不同字段。

## 5 文件监控逐项说明

### 5.1 三种规则的写法

下面都是 `FilesMonitoring` 中的配置片段：

```yaml
FilesMonitoring:
  fils:
    - '/opt/app/a.conf|/opt/app/b.conf'
  dir:
    - '/opt/app/config/|/etc/cron.d/'
  search:
    - 'authorized_keys,/root|/home'
```

| 子字段 | 规则格式 | 具体含义 |
|---|---|---|
| `fils` | `路径1\|路径2[,MD5a,MD5b...]` | 检查每个路径；如果路径是目录，也递归检查其中的普通文件 |
| `dir` | `目录1\|目录2[,MD5a,MD5b...]` | 递归检查每个目录内所有普通文件 |
| `search` | `精确文件名,目录1\|目录2[,MD5a,MD5b...]` | 在所有根目录递归找该文件名，对每个匹配文件分别检查 |

文件规则里的 `|` 表示“全部检查”。上面的两个配置文件都必须检查，两个目录也都必须检查。`search` 的第一个逗号用于分隔文件名和根目录；后续逗号用于分隔 MD5。

`search` 匹配完整文件名，例如 `authorized_keys` 不会匹配 `authorized_keys.bak`，也不会匹配大小写不同的名字。新文件模块始终递归处理目录，没有可配置的 `recursive` 开关；不需要自行添加该字段。

单个路径或文件名如果本身含 `|`、`,`，会与现有规则分隔语法冲突；仅加 YAML 引号不能解决。按现有格式应避免使用这种路径作为规则目标。

### 5.2 不写 MD5 时怎样比较

```yaml
FilesMonitoring:
  fils:
    - '/opt/app/a.conf'
```

假设同一个常驻 Agent 进程依次观察到以下结果：

| 轮次 | 文件情况 | 检测结果 | 下一轮拿什么比较 |
|---|---|---|---|
| 第 1 轮 | 内容是 A | 首次建立基线；现有文件不算新增 | A |
| 第 2 轮 | 仍是 A | `unchanged`，没有变化告警 | A |
| 第 3 轮 | 变成 B | `modified`，记录前后 MD5 并告警 | B |
| 第 4 轮 | 仍是 B | `unchanged`，不重复上一轮修改告警 | B |
| 第 5 轮 | 又变回 A | `modified`，因为与上一轮 B 不同 | A |

它使用**滚动基线**，即与上一次成功扫描比较。一次修改不是永久异常。详细日志和指标成功写出后，程序才提交新的基线；模块读取失败时保留旧基线，避免误判。

### 5.3 写了 MD5 时怎样比较

```yaml
FilesMonitoring:
  fils:
    - '/opt/app/a.conf|/opt/app/b.conf,d41d8cd98f00b204e9800998ecf8427e,900150983cd24fb0d6963f7d28e17f72'
```

整行中逗号后面的所有 MD5 组成一个“已知正常值集合”。这一行的每个文件都可以匹配其中任意一个值，不按位置把第一个文件与第一个 MD5 配对，也不要求全部正常值都被某个文件用到。两个文件同时命中同一个值也正常。

上面的 MD5 是演示值，不代表你的业务文件正常版本。应在可信的目标文件上执行：

```sh
md5sum /opt/app/a.conf /opt/app/b.conf
```

把输出每行开头的 32 位摘要填入 YAML。程序只接受 32 位十六进制 MD5，不能填 `MD5a`、`md51`、文件名或整行 `md5sum` 输出。

**配置了正常值，也不会在首次遇到未知值时直接报不匹配。** 当前实现的效果如下：

| 场景 | 结果 |
|---|---|
| 当前 MD5 命中任一配置正常值 | 内容检查放行，明细通常为 `matched` |
| 首轮现有文件 MD5 不在配置集合 | 接受当前内容，按该完整路径建立基线；不产生 MD5 不匹配告警 |
| 已跟踪的未知值一直不变 | 正常，不重复告警 |
| 未知值变成另一个未知值 | `modified`，随后滚动记录新值 |
| 已跟踪的已知正常值变成未知值 | `modified`，因为未知新值与上一轮不同 |
| 一个正常值变成另一个配置正常值 | 内容检查放行 |
| 未知值变成配置正常值 | 内容检查放行 |
| 运行中新增一个文件，且 MD5 是正常值 | 仍可能产生 `added`，因为文件清单新增与内容是否放行是两件事 |
| 已跟踪文件被删除 | 产生 `deleted`；明确配置路径缺失还会有 `missing` |

未知值只学习到这个文件路径的基线，不会自动追加进 YAML 的正常值集合，也不会自动成为另一个文件的正常值。规则明细的 `matched` 是命中已知正常值的文件数，`baseline_tracked` 是按独立基线跟踪的文件数。

如果你的目标是“首次未知内容也必须立即拒绝或一直告警”，现有这套 MD5 规则不能实现这种效果。

### 5.4 文件缺失和搜索无结果

| 状态或告警 | 什么时候产生 | 应怎样理解 |
|---|---|---|
| `missing` | 配置要求检查的文件或根目录不存在 | 这是必需路径缺失，每轮仍缺失就仍告警 |
| `not_found` | 一条搜索规则没有找到匹配文件 | 例如要求找 `authorized_keys`，但没有搜索结果 |
| `added` | 后续扫描出现先前清单没有的文件 | 首轮已存在文件通常不会这样报告 |
| `modified` | 需要基线比较的文件内容变化 | 记录前后 MD5 |
| `deleted` | 先前清单有的文件后来消失 | 文件重命名通常表现为旧路径删除、新路径新增 |
| `inspection_error`、`collection_error` | 权限不足、文件读取失败、遍历失败等 | 本轮采集不完整；保留旧基线，先处理读取问题 |

缺失路径不会阻止其余正常可读路径建立基线；缺失路径后来出现，会报告新增。不存在的搜索根目录也会记录缺失。多个规则覆盖同一文件时，各规则分别判断；只要其中一条基线规则发现修改，就可能产生修改告警，不能指望另一条正常值规则免除它。

### 5.5 文件检测的实际范围

只检查普通文件内容，不沿目录符号链接继续扫描，也不对特殊设备文件计算 MD5。已经跟踪的文件如果被换成符号链接或特殊文件，会显式报错。仅修改权限、属主、时间戳而内容不变，不属于内容修改。

Agent 自己的输出目录、状态路径和生成的日志/指标会自动排除，避免程序写日志引发自己的变化告警。MD5 用于比较内容，不能当作文件数字签名。

文件检测是周期采样。例如 10:01 修改、10:02 恢复，而扫描发生在 10:00 和 10:05，可能看不到这次短暂变化。

## 6 进程监控逐项说明

### 6.1 只检查关键服务

配置片段：

```yaml
ProcessMonitoring:
  exists:
    - '/usr/sbin/sshd -D'
    - '/opt/app/bin/worker --config /etc/app/worker.yaml'
```

这表示每轮都必须满足两项：sshd 的对应完整命令存在，而且 worker 的对应完整命令存在。每行是一项独立的必需规则。

程序从 Linux `/proc` 读取进程，以完整命令及参数比较，不是按可执行文件名、子字符串或安装路径是否存在比较。空白会归一化，但参数、参数顺序、路径等仍须匹配。例如 `/usr/sbin/sshd -D-extra` 不能满足 `/usr/sbin/sshd -D`。

填写前在目标机查询真实进程。以下命令是查配置值的辅助命令，不是 Agent 的运行依赖：

```sh
pgrep -a sshd
# 将 1234 替换成要检查的服务 PID，读取其实际命令参数。
sudo cat /proc/1234/cmdline | tr '\0' ' '
printf '\n'
```

某些进程会改写自身标题，`/proc` 中的显示值可能与 systemd 的 `ExecStart` 不完全相同；以本机实际值为准。不要把 SSH 客户端 `ssh` 写成 sshd 服务的替代项。

### 6.2 允许同一个服务使用多个启动形式

```yaml
ProcessMonitoring:
  exists:
    - '/opt/app/bin/worker --config /etc/app.yaml|/usr/local/bin/worker --config /etc/app.yaml'
```

这一行表示两个命令任意一个存在即可满足规则。可以填写三个或更多备选命令。不要拆成两个列表项，否则会变成要求两个命令同时存在。

**相同符号在两个模块的含义不同：**文件规则 `A|B` 要检查 A 和 B；进程 `exists` 的 `A|B` 只要 A 或 B 任意一个在运行。

### 6.3 开启全机进程变化检测

```yaml
ProcessMonitoring:
  Process: {}
```

这会启用全机进程清单比较。第一次完整扫描建立基线；后续按完整命令和实例数量比较，新增或数量增加产生 `added`，消失或数量减少产生 `deleted`。

假设某个 worker 命令第一轮有 2 个实例，第二轮只剩 1 个，即使仍有 worker 运行，也会产生实例减少告警。进程 PID 变化但完整命令和实例数相同，通常不会单独产生变化告警。

全机模式也包括临时命令、SSH 会话和没有参数的内核线程等。繁忙节点可能频繁出现变化告警。当前没有“只比较某几个业务命令变化”的 `include` 字段。

### 6.4 白名单能免除什么

```yaml
ProcessMonitoring:
  exists:
    - '/usr/sbin/sshd -D'
  Process:
    whitelist:
      - '/usr/sbin/sshd -D'
      - '/opt/app/bin/worker --config /etc/app/worker.yaml'
```

白名单只抑制这些完整命令的清单变化告警。它们仍出现在当前清单和日志里，也仍参与 `exists` 存活检查。如果 sshd 在白名单中，但 `exists` 要求它必须运行，sshd 全部退出后仍会报缺失。

白名单支持完整命令精确匹配；同一项内可用 `|` 列举多个完整命令，不支持通配符、前缀或正则。`whitelist: []` 只是空白名单，会监控全部进程变化。

想降低全机变化告警，应删除整个 `Process` 子段，保留需要的 `exists`。`Process: {}` 是开启，不能用它关闭。只配置 `exists` 时仍会读取并记录完整进程清单，但不会对全机清单增删产生告警。

## 7 成功 SSH 登录采集

### 7.1 字段和默认值

| 字段 | 默认值 | 用途及范围 |
|---|---|---|
| `enabled` | `true` | 开启成功登录采集；要关闭应明确写 `false` |
| `source` | 新格式默认 `journal`；纯旧格式默认 `wtmp` | 数据来源，允许 `journal`、`authlog`、`jsonl`、`wtmp` |
| `journal_command` | `journalctl` | journal 采集程序名或路径；不要追加 Shell 参数 |
| `path` | 旧默认 `/var/log/wtmp`；authlog 未改此默认时转换为 `/var/log/auth.log` | 非 journal 源的日志路径；jsonl 应明确填写实际文件 |
| `last_command` | `last` | wtmp 使用的可执行程序名或路径 |
| `initial_lookback_hours` | `24` | journal、authlog、wtmp 首次回看小时数，允许 1–8760；显式 0 会恢复 24 |
| `timeout_seconds` | `10` | 执行采集程序的超时秒数，允许 1–3600 |
| `max_records` | `1000` | 每轮分页处理上限，允许 1–100000；journal 按候选事件、authlog 按日志行分页，实际登录条数可能更少 |

为了避免依赖新旧格式默认选择，建议总是明确填写 `source`。

### 7.2 journal 配置

```yaml
login:
  enabled: true
  source: journal
  journal_command: journalctl
  initial_lookback_hours: 24
  timeout_seconds: 10
  max_records: 1000
```

程序读取 sshd 和 sshd-session 的成功认证事件，记录用户、登录来源 IP、真实发生时间、认证方式和可获得的终端。认证行没有终端时记为 `N/A`。非交互 SSH 命令也可能通过成功认证日志获得登录记录；失败登录不属于这个成功登录采集模块。

第一次从回看窗口开始；之后从持久化 journal 游标续读。已有游标时修改 initial_lookback_hours，不会自动重新回看已读位置之前的历史。`max_records` 不表示只保存最后 1000 次登录，积压会留到后续轮次。系统日志必须保留覆盖停机时间，已被操作系统清理的数据无法恢复。

常驻服务中登录采集跟随 `setup.interval_seconds`，例如 300 秒意味着通常到下一轮巡检才读到新事件。命令采集的 1000 毫秒轮询不会让登录也变为每秒采集。自动安装的 SSH 入口可触发一次额外巡检，但认证日志可见时机仍会影响该次采集，应以最终巡检记录为准。

### 7.3 authlog 配置

```yaml
login:
  enabled: true
  source: authlog
  path: /var/log/auth.log
  initial_lookback_hours: 24
  timeout_seconds: 10
  max_records: 1000
```

如果目标系统使用 `/var/log/secure`，改成那个实际路径。首次读取当前文件并按回看窗口筛选；之后按保存的字节位置增量读取。程序尝试接续保留的未压缩 `path.*` 轮转日志；若轮转历史缺失、被压缩或截断到无法恢复，会明确报错，不能保证补回所有记录。

### 7.4 jsonl 配置和数据示例

```yaml
login:
  enabled: true
  source: jsonl
  path: /opt/audit/ssh-logins.jsonl
  timeout_seconds: 10
  max_records: 1000
```

适合演示或已有自定义登录日志。每一物理行是一条 JSON 对象，例如：

```json
{"id":"login-001","user":"root","source_ip":"192.168.1.10","login_time":"2026-10-14T10:00:00+08:00","terminal":"pts/0","method":"publickey"}
```

`user`、带时区的 RFC3339 `login_time`、`terminal` 必须填写；没有终端填 `N/A`。`source_ip` 非空时必须是合法 IP。建议生产方提供稳定且唯一的 `id`。新格式监控中，首次读取文件内尚未记录的条目，按状态去重并分页；它不按 `initial_lookback_hours` 截掉旧记录。

### 7.5 wtmp 配置

```yaml
login:
  enabled: true
  source: wtmp
  path: /var/log/wtmp
  last_command: last
  initial_lookback_hours: 24
  timeout_seconds: 10
  max_records: 1000
```

需要支持 `--time-format iso` 的 util-linux `last`。只覆盖系统实际写入 wtmp 的会话，可能包含其他登录会话，并非严格仅 SSH；也不能保证记录所有非交互 SSH 认证。要逐次查看成功 SSH 认证事件，应选 journal 或完整 authlog。

保留 `state_file` 和对应 `.logins`，登录游标会跨重启继续。随意删除状态或改 `state_file`，会让程序失去原先的读取位置，可能重新采集历史记录。切换数据源或路径时需要按迁移流程处理游标，不能把旧游标直接当新来源的状态使用；详见[部署调试与测试命令手册](部署调试与测试命令手册.md)。

## 8 操作命令采集

### 8.1 开启前要具备什么

`history` 读取已有命令日志，不会自动安装命令记录脚本，也不会自动读取全部 Shell、系统调用或其他用户的所有操作。目标机应已有记录机制持续往日志追加约定格式的数据，例如已有的 `/etc/profile.d/history-audit.sh`。

必须有可读的日志文件、非空 `server`、支持命令入库确认的配套 Master。持续采集应使用常驻 `-service`。不需要此功能时省略 `history`，或明确设置 `enabled: false`。

配置片段，需替换同名 `history` 和 `server`：

```yaml
history:
  enabled: true
  path: /var/log/history.log
  timezone: Local
  poll_interval_ms: 1000
  max_records: 100

server:
  - '172.22.0.27:55555'
```

### 8.2 字段和源日志格式

| 字段 | 默认值 | 用途及范围 |
|---|---|---|
| `enabled` | 关闭；只有明确 `true` 才启用 | 是否采集操作命令；`history: {}` 也不会开启 |
| `path` | `/var/log/history.log` | 已有命令源日志路径 |
| `timezone` | `Local` | 按节点本地时区解释源日志；也可以填写明确时区 |
| `poll_interval_ms` | `1000` | 追平后轮询间隔，单位毫秒，允许 100–60000；0 恢复默认 |
| `max_records` | `100` | 每批最多处理的物理行数，允许 1–1000；空行也计数，0 恢复默认；另有约 512 KiB 单页读取预算 |

源日志每行格式：

```text
[2026-10-14 10:00:00] [root] [pts/0] [systemctl status agent.service]
[2026-10-14 10:00:02] [admin] [pts/1] [cat /etc/hosts]
```

这两条会形成两条操作命令记录。时间没有时区，按 `history.timezone` 解释。这个设置应与记录脚本使用的 `date` 时区一致；配置错时区会造成发生时间偏移。记录包含日志里的命令文本，不包含该命令的执行退出码、输出或成功判断。

### 8.3 首次补传和后续采集

首次从文件开头补传全部已有记录，每批最多 `max_records` 条，积压时连续分批处理，不是每秒只处理一批。追平后再按 `poll_interval_ms` 轮询新增内容。这与 300 秒文件巡检、登录回看时长都独立。

程序先加密保存待发批次和后续读取位置，再上报。每一个 `server` 都确认入库后才清空待发批次并继续。某台主控无法确认时会重传，已经确认的主控可能再次收到相同记录，由稳定 ID 去重。多主控配置会让慢端或不可达端拖住这个通道。

每条报文等待匹配的入库确认最多约 2 秒，网络需要允许 UDP 请求和回复；1000 毫秒轮询不表示从命令执行到页面出现一定恰好 1 秒，还取决于源日志写入、补传积压、网络及页面刷新。

重启继续使用 `.commands` 状态。不要删除它来“清缓存”，删除会从头补传并生成新记录 ID。无参数单次运行只处理一批，不适合用来持续追平大日志。

普通操作命令进入主控“安全事件 → 操作命令”，不自动触发告警 webhook。源日志格式错误等解析异常可以产生告警，与普通命令记录不同。

### 8.4 哪些命令不会自动出现

没有写入指定日志的命令，Agent 无法自动恢复；关闭写日志的 Shell、未接入记录脚本的用户或非交互任务，都可能不在该源日志中。缺少结尾换行的最后一行，会等记录写完整后处理。包含实际换行的多行命令应由生产脚本转义为单行，否则现有格式不能可靠还原。

日志必须是 UTF-8。格式错误、空白命令或记录 JSON 编码后超过 56000 字节，会转成带字节位置的 `history / parse_error` 告警，原文留在源日志。单个物理行超过 1 MiB 时会读取失败并停止推进。

Agent 不清空、修改或轮转源日志。日志被替换、截断或历史内容被改写时，会停止推进并记录错误。修改 history 的 path 或 timezone 后复用原命令状态，也会因来源不一致而拒绝推进；即使两个时区当前偏移相同，修改名称仍改变来源标识，而只改顶层 timezone 不会改变它。需要保留源日志、加密游标及未确认批次，按迁移方案处理，不能把源日志与 Agent 按日期生成的日常日志混为一谈。

## 9 数据上报和配置连接

### 9.1 server 怎样填

配置片段：

```yaml
server:
  - '172.22.0.27:55555'
  - '192.168.0.2:55555'
  - '[2001:db8::1]:55555'
```

替换成实际接收主控。允许域名、IP、域名加端口、IP 加端口，端口范围 1–65535；裸域名或 IP 默认 UDP 55555。IPv6 带端口必须用方括号。不要填 `https://主控页面`、`/api` 路径或 Web 服务端口。

多个地址表示全部发送，不是随机选择、主备切换或只发送第一个。常驻服务会向它们发送心跳、扫描摘要、告警、成功登录以及启用后的操作命令。Agent 不需要你手工填写机器 IP，会按到配置主控的实际网络路由获取本机地址；登录记录里的来源 IP 表示登录者地址，是不同含义。

### 9.2 两条连接分别做什么

```text
Agent ──主动 TCP 连接，通常 55556──→ 配置 Master
      ←────────加密配置───────────

Agent ──UDP，通常 55555───────────→ server 列表中的每一台接收 Master
              心跳、检测结果、告警、成功登录、操作命令
```

| 对比项 | TCP 配置连接 | YAML server 的 UDP 上报 |
|---|---|---|
| 用途 | 下发配置、连接握手和控制消息 | 发送采集结果 |
| 地址从哪里来 | 服务启动参数、环境变量、已保存连接设置等 | YAML 的 `server` |
| 默认端口 | TCP 55556 | UDP 55555 |
| 自动安装服务默认地址 | `172.22.0.27` | Agent 未配置 server 时为空；页面模板内容需另行核对 |
| 改 server 是否影响它 | 不影响 TCP 地址 | 下发新配置后变更数据接收端 |

自动安装的 `agent.service` 使用启动参数固定连接 `172.22.0.27`。前台和单次模式可通过 `-master` 或 `ANQUAN_MASTER` 指定配置主控；多个配置主控按顺序选择连接。YAML 里没有 `master` 或 `master_port` 字段。

`server: []` 只关闭 UDP 数据上报，TCP 配置连接仍可以正常工作。因此“页面已应用配置”不等于“平台已收到巡检数据”：需要继续核对 `server` 和 UDP 网络。启用 `history` 时不能使用空列表，否则整份配置校验失败。

### 9.3 上报以后一定能看到通知吗

常规心跳、巡检、告警和登录使用 UDP 尽力发送；本地发送成功不证明主控一定收到，当前没有这几类数据的持久重传确认。命令采集单独支持入库确认和持久重试。

常驻 UDP 心跳固定约 30 秒，与巡检间隔无关，不支持在 YAML 添加 `heartbeat_interval`。配套主控通常在超过 90 秒没有有效活动后显示异常离线。收到心跳主要更新在线状态，不会形成一条普通安全事件。TCP 连接的握手和 ping 也会更新主控在线时间，所以 server 为空而 TCP 正常时，机器仍可能在线，但没有新的 UDP 巡检安全事件。

文件告警和新入库的成功登录，可以由 Master 发往已启用的通知地址。**通知 URL 在主控通知管理中配置，不在 Agent YAML 的 `server` 里填写。**普通命令记录不会自动发送告警通知。还需要主控通知配置启用且发送成功，不能仅凭 YAML 有 `server` 就认定机器人已收到消息。

## 10 日志 指标和巡检间隔

### 10.1 setup 字段

| 字段 | 默认值 | 实际效果 |
|---|---|---|
| `logs` | `/var/log/时间anquan.log` | 每行一条 JSON，追加到当天文件 |
| `prom` | `/var/lib/node_exporter/textfile_collector/process_monitor.prom` | 每轮原子覆盖同一个 Prometheus 文件 |
| `interval_seconds` | `300` | `-service` 巡检周期，允许 1–86400 秒；0 恢复 300 |

路径后缀为 `.log` 或 `.prom` 时按文件路径处理；否则按目录补上默认文件名。建议明确写完整文件名，避免把不符合后缀的自定义名字误当目录。

### 10.2 日志文件怎样生成

| logs 配置 | 北京时间 2026 年 10 月 14 日的文件 |
|---|---|
| `/var/log/时间anquan.log` | `/var/log/20261014anquan.log` |
| `/var/log/anquan_{date}.log` | `/var/log/anquan_20261014.log` |
| `/var/log/anquan.log` | `/var/log/20261014_anquan.log` |
| `/var/log/anquan/` | `/var/log/anquan/20261014anquan.log` |

占位符只能放在文件名，不能放在目录名；`logs` 使用 `时间` 或 `{date}`，不接受 `{time}`。北京时间跨过零点后，下一次写入选择新的日期文件，并非零点必须立即生成一个空文件。旧日期文件不会自动删除。

日志包含正常模块结果、完整进程清单、告警和成功登录，例如 `files_result`、`process_result`、`login_result`、`alert`、`ssh_login`、`scan_complete`。新格式不再生成每轮一个时间戳命名的完整 JSON 报告。

### 10.3 指标文件怎样使用

`setup.prom` 始终是固定文件。兼容旧模板时，文件名中的 `时间`、`{date}`、`{time}` 会被移除。这个路径写入 `anqu_snapshot_` 前缀的快照指标，包含本轮的 run_id；另有 `output_dir/textfile/anqu.prom` 保存 `anqu_` 前缀的稳定最新状态指标。查询时请根据抓取的是哪个文件使用对应名称。

设置 `prom` 只会生成文件，不会安装 node_exporter、自动开启 textfile collector 或自动配置 Prometheus 抓取。Agent 自身不提供 HTTP metrics 接口。需要让 node_exporter 读取对应目录。例如默认路径需要实际的 exporter 配置含 `--collector.textfile.directory=/var/lib/node_exporter/textfile_collector`；想抓取 `anqu_` 指标，则需要让 exporter 读到 `output_dir/textfile/anqu.prom`。

| 抓取的文件 | 对应的指标名称示例 |
|---|---|
| setup.prom，默认 `/var/lib/node_exporter/textfile_collector/process_monitor.prom` | `anqu_snapshot_collection_success`、`anqu_snapshot_alerts`、`anqu_snapshot_files_change`，带 host 和 run_id |
| output_dir/textfile/anqu.prom，默认 `/usr/local/anquan/textfile/anqu.prom` | `anqu_collection_success`、`anqu_alerts`、`anqu_files_change`、`anqu_process_exists`、`anqu_ssh_logins_new` |

`collection_success: true` 表示采集完成，**不表示没有告警**；缺少必需进程可以是一次成功采集出来的异常结果。

### 10.4 三种频率分别控制什么

| 参数或固定周期 | 示例 | 控制对象 |
|---|---|---|
| `setup.interval_seconds` | 300 秒 | 文件、进程、成功登录巡检 |
| `history.poll_interval_ms` | 1000 毫秒 | 追平后检查操作命令日志的新增内容 |
| 固定 UDP 心跳 | 30 秒 | 常驻在线状态上报 |

常驻扫描不会重叠运行。单轮耗时超过周期时会跳过来不及执行的节拍。单轮出错会记录错误并继续后续轮次。无参数单次执行只运行一轮，不会因为配置写了 300 就留在后台。

周期越短、扫描范围越大，文件读取和 MD5 计算次数越多；尤其从 `/`、`/var` 之类大目录递归搜索时，应按需要缩小范围。

## 11 怎样让配置真正生效

### 11.1 页面下发方式

1. 在目标节点安装并运行配套 Agent，让它主动连接配置 Master。新 Linux 节点以 root 无参数执行上传的 Agent，可以自动安装并启动 `agent.service`。
2. 打开“管理设置 → Age 配置加密”。
3. 粘贴这份 YAML，修改目标路径、进程命令、`server` 和所需开关。
4. 点击“下发配置”，选择目标机器并确认。
5. 等待目标状态显示“已应用”。在线节点通过现有 TCP 长连接接收，离线节点在重连后接收。
6. 查看 Agent 日志的新扫描，以及主控实际收到的数据。

“下发配置”不需要先点击“加密配置”或“存储模板”。页面的不同操作并不相同：

| 页面操作 | 效果 | 是否让 Agent 使用新配置 |
|---|---|---|
| 编辑 YAML | 改页面输入 | 否 |
| 存储模板 | 原样保存共享模板，方便下次恢复 | 否 |
| 恢复示例 | 恢复已存模板；没有时使用内置示例 | 否 |
| 加密配置并下载 | 生成 `config.age` | 否，仍需实际部署 |
| 下发配置并选择机器 | 保存该机器的配置分配并推送 | 是，Agent 成功校验和切换后确认 |

已有模板可能包含其他业务路径、特定进程或主控 IP。恢复后仍须核对，不能把它当作适合所有机器的配置。

Master 页面只检查非空、最多 4 MiB、单份 YAML 映射及基本语法等；字段是否受支持、MD5 是否合法、数值范围和模块组合是否有效，仍由 Agent 严格校验。因此“加密成功”或“提交成功”之后仍可能显示“应用失败”，需要查看目标应用状态和错误原因。

有效下发配置原子保存为 **Agent 可执行文件旁的 `config.master.age`**。常驻 Agent 在当前扫描完成后切换，再按新配置立即扫描，不需要为了平台下发额外重启。非法字段、非法 MD5、无法保存或无法切换的配置不会覆盖当前有效配置；页面会显示应用失败或仍待应用等状态。

“已应用”确认的是配置校验、保存和切换，不表示目标业务进程存在，也不表示日志采集权限、UDP 收件或通知发送全部成功。

### 11.2 本地加密文件方式

适合需要本地回退配置的机器。页面编辑并点击“加密配置”，下载 `config.age`，放在 Agent 可执行程序旁。例如：

```text
/usr/local/anquan/
  anquan
  config.age
```

Agent 运行时不直接读取明文 `config.yaml`。配置更新不用重新编译，但必须重新加密。替换本地文件后，常驻服务需要重启；程序不会因为明文 YAML 或本地密文文件刚被改动就自动切换。

下面命令在目标 Linux 节点执行，假设下载后的新密文放在 `/tmp/config.age.new`，且该节点使用自动安装的 `agent.service`：

```sh
# 若旧回退文件存在，先保存一份备份。
if [ -f /usr/local/anquan/config.age ]; then
  sudo cp -p /usr/local/anquan/config.age /usr/local/anquan/config.age.backup
fi

# 先复制到同目录临时文件，再重命名替换，避免程序读到半份文件。
sudo install -m 600 /tmp/config.age.new /usr/local/anquan/config.age.new
sudo mv /usr/local/anquan/config.age.new /usr/local/anquan/config.age
sudo systemctl restart agent.service
sudo systemctl status agent.service --no-pager
sudo journalctl -u agent.service -n 50 --no-pager
```

如果部署用的是其他服务名，请替换 `agent.service`。密文需要保留完整的 AGE 文件首尾标记；损坏密文不是“没有配置”，仍会拒绝读取。启动时存在但损坏的本地 config.age 会直接导致启动失败，即使还有平台缓存也不能用它绕过这一步，应恢复有效回退文件。

### 11.3 配置优先级

```text
有效主控配置及其 config.master.age 缓存
                  ↓ 没有分配时
可执行文件旁的本地 config.age
                  ↓ 也没有时
常驻服务继续连接并等待下发，不执行巡检
```

主控仍给机器分配配置时，本地 `config.age` 只是回退，修改它不会覆盖平台配置。主控明确返回未给本机分配配置后，Agent 清除主控缓存，再恢复本地回退；没有本地回退则继续等待。主控短暂不可达时仍可使用已经保存的有效配置缓存。

没有有效配置的单次运行会限时同步，仍未取得配置则退出 1；不会无限等待。新机器等待配置时的 TCP 在线状态，不等于已经开始巡检。

### 11.4 重启和切换配置对基线的影响

| 操作 | 文件和进程基线 | 登录和命令游标 |
|---|---|---|
| 同一常驻进程继续下一轮 | 与上次成功扫描比较 | 从上次读取位置继续 |
| 重启 Agent | 首次完整扫描重新建立 | 状态路径不变时继续保留 |
| 新平台配置应用 | 重新建立，即使只修改 server 或 interval | 状态路径及对应数据源不变时继续保留 |
| 反复无参数单次执行 | 每次建立当次运行基线 | 保留游标，继续采集 |
| 修改 state_file 或删除相关状态 | 新位置没有原状态 | 失去对应旧游标，可能回看或重传 |

所以，不能用“执行一次 → 修改文件 → 再执行一次”来验证无 MD5 的跨进程变化检测。应在同一个常驻服务保持运行时修改测试文件，再观察下一轮。停机期间或新配置建立基线之前已经发生的内容变化，会被作为新的初始状态。

不要为了让配置生效随意删除整个 state 目录，这会影响登录去重和命令重传。

## 12 怎样验证配置后的效果

### 12.1 先看服务和日志

以下在目标 Linux 节点执行，适用于默认路径：

```sh
sudo systemctl status agent.service --no-pager
sudo journalctl -u agent.service -n 100 --no-pager

# 文件名日期按北京时间选取，与 Linux 系统本地时区无关。
anqu_log_day=$(TZ=Asia/Shanghai date +%Y%m%d)
sudo tail -n 100 "/var/log/${anqu_log_day}anquan.log"

# 查看本轮状态和本轮告警数量。
sudo grep -E '^anqu_(collection_success|alerts|ssh_logins_new)' \
  /usr/local/anquan/textfile/anqu.prom
```

日志中应能看到 `scan_started` 和 `scan_complete`，开启的模块应有对应结果。出现 `alert` 要看 `module`、`kind`、`target` 和具体错误；不能仅看服务状态是 active 就认为全部正常。

### 12.2 在独立测试目录验证文件增删改

选择专门的测试节点或测试 Agent。先把测试目录准备好：

```sh
sudo mkdir -p /opt/anqu-test/watched
printf 'version=1\n' | sudo tee /opt/anqu-test/watched/demo.conf >/dev/null
```

将该节点的文件监控改为以下片段，并把测试用间隔改成 10 秒，通过页面下发。该片段替换原 `FilesMonitoring` 和 `setup`；其余上报、登录等配置按需要保留。

```yaml
FilesMonitoring:
  dir:
    - '/opt/anqu-test/watched'

setup:
  logs: '/var/log/时间anquan.log'
  prom: /var/lib/node_exporter/textfile_collector/process_monitor.prom
  interval_seconds: 10
```

等待“已应用”并确认首次 `scan_complete`。后面每一步之间都等一轮扫描完成，保持同一个 Agent 服务持续运行：

| 操作 | 下一轮预期效果 |
|---|---|
| 首轮扫描已存在的 `demo.conf` | 建立基线，不把它当作新增 |
| 把 `demo.conf` 内容改成 `version=2` | `modified`，有前后 MD5 |
| 保持内容不变再等一轮 | 正常，不重复修改告警 |
| 新建 `new.conf` | `added` |
| 删除测试目录内的 `new.conf` | `deleted` |
| 把 `demo.conf` 改回 `version=1` | `modified`，因为上一轮记录的是 version=2 |

可执行的修改和新增示例：

```sh
printf 'version=2\n' | sudo tee /opt/anqu-test/watched/demo.conf >/dev/null
# 等下一轮完成后，再新增一个文件。
printf 'new=true\n' | sudo tee /opt/anqu-test/watched/new.conf >/dev/null
```

验证后恢复该测试节点所需的正式间隔和规则。验证关键进程缺失时使用专门的测试进程，不要为了试告警停止远程 SSH 服务。

### 12.3 登录 命令和平台验收

| 要确认的效果 | 操作 | 预期证据 |
|---|---|---|
| 成功登录采集 | 通过正常 SSH 建立一次新的成功连接，等待下一轮 | Agent 的 `ssh_login` 日志有用户、来源 IP、发生时间 |
| 操作命令采集 | 由已有记录脚本追加一条符合格式的测试命令，启用 history | 主控“操作命令”有记录，待发批次取得入库确认 |
| 平台接收结果 | 配置实际 server 并等待扫描 | 主控收到扫描摘要或新安全事件 |
| 持续在线 | 保持常驻服务、TCP 配置连接或 UDP 活动正常 | 主控在线状态持续更新；是否收到采集数据还要核对新巡检记录 |
| 机器人通知 | 主控启用通知地址后产生一条新的测试告警 | 主控通知状态及接收端实际收到消息 |
| Prometheus 采集 | 配置 node_exporter 读取指标目录并被抓取 | exporter 指标可见，Prometheus 查得到相关序列 |

只见本地日志而主控没有事件，先查 UDP 上报；只见主控事件而机器人没有消息，再查通知配置和发送状态。页面“已应用”单独验证配置投递，不代替上述验收。

### 12.4 单次执行的退出码

在**已经安装的程序路径**执行：

```sh
sudo /usr/local/anquan/anquan
anqu_exit_code=$?
printf 'exit=%s\n' "$anqu_exit_code"
```

| 退出码 | 含义 |
|---|---|
| `0` | 完成巡检，没有巡检告警 |
| `2` | 完成巡检，发现告警 |
| `1` | 配置、采集、输出、状态保存或通知发送等出现错误 |

单次默认静默，终端没有输出不代表没执行，查看日志和退出码。当前 CLI 没有 `-once`、`-config`、`-check-config` 参数；使用无参数单次执行或 `-service` 常驻执行。新上传位置无参数执行可能触发自动安装，验收单次行为请使用上面的已安装路径。

## 13 按需求开启或关闭模块

| 想要的行为 | 正确配置方式 |
|---|---|
| 关闭新文件监控 | 删除整个 `FilesMonitoring` 段 |
| 关闭进程监控 | 删除整个 `ProcessMonitoring` 段 |
| 只检查关键进程 | 保留 `ProcessMonitoring.exists`，删除其 `Process` 子段 |
| 开启全机进程变化检测 | 添加 `Process: {}` 或含 whitelist 的 Process 段 |
| 关闭成功登录采集 | `login.enabled: false` |
| 关闭操作命令采集 | 省略 history 或 `history.enabled: false` |
| 关闭 UDP 上报但保留配置下发 | `server: []`，同时关闭 history |
| 加快文件 进程和登录巡检 | 调整 `setup.interval_seconds`，然后下发新配置 |

`FilesMonitoring: {}` 和 `ProcessMonitoring: {}` 缺少有效规则，会拒绝；顶层这些监控段写 `null` 也会拒绝。要关闭请省略。删除 `login` 不会关闭登录，默认仍启用。

新格式建议始终保留 `setup`、明确 `login.enabled` 和 `server`。只剩基础目录而没有任何新格式字段时，会落回旧格式的默认选择，旧 md5 和 existence 默认启用，可能因缺少必填规则而拒绝。不要用删除所有配置段的方式制造“空配置”。

只需要成功登录采集和平台上报的完整示例：

```yaml
output_dir: /usr/local/anquan
state_file: state/md5.json
timezone: Asia/Shanghai

login:
  enabled: true
  source: journal
  journal_command: journalctl
  initial_lookback_hours: 24
  timeout_seconds: 10
  max_records: 1000

server:
  - '172.22.0.27:55555'

setup:
  logs: '/var/log/时间anquan.log'
  prom: /var/lib/node_exporter/textfile_collector/process_monitor.prom
  interval_seconds: 60
```

这份配置没有文件和进程监控，每分钟采集成功登录；常驻心跳仍每 30 秒发送。

## 14 常见问题和误配置

| 现象 | 常见原因 | 调整方法 |
|---|---|---|
| 页面应用失败，提示未知字段 | fils 改成 files、大小写错误、添加未支持字段 | 按原字段名修改 |
| 总是报某路径 missing | 目标不存在、拼错、相对路径理解错 | 在目标机核对；不需要就删除该规则 |
| authorized_keys 总是 not_found | 搜索范围没有该文件 | 必需文件应检查原因；非必需则移除 search 规则 |
| 第一轮未知 MD5 没告警 | 当前实现首次接受未知值建立基线 | 按第 5 节的后续变化逻辑验收 |
| 修改文件后第二次单次执行没报修改 | 每次单次运行重建基线 | 用同一个常驻进程跨轮次检测 |
| 重启后停机期间修改没告警 | 重启时重建初始基线 | 了解生命周期边界，保持常驻检测 |
| sshd 明明在运行却报缺失 | 完整命令或参数不匹配 | 从本机 /proc 读取准确值 |
| 加白名单以后仍报 sshd 缺失 | 白名单不免除 exists | 保留真实必需检查，恢复进程或修正命令 |
| 全机进程变化告警很多 | 开启了 Process，临时命令/会话不断变化 | 删除 Process 子段，只保留 exists |
| 关闭 login 后却仍看到旧登录 | 主控保存的历史记录不会因配置改变消失 | 核对新轮次，不把历史记录当新采集 |
| 改本地 config.age 没效果 | 平台配置优先，或未重启本地配置服务 | 通过平台更新有效分配；本地方式按第 11 节 |
| 页面已应用但平台没有检测事件 | server 空、填了网页地址、UDP 不通 | 检查接收地址及 UDP 端口 |
| history 开启后 YAML 被拒绝 | server 为空 | 填接收主控或关闭 history |
| history 报读文件错误 | 源日志不存在、权限不足、被轮转/截断 | 核对记录脚本、实际日志及游标，不删除状态掩盖问题 |
| 命令积压不再推进 | 某个 server 未返回入库确认 | 核对每个接收 Master 版本和双向 UDP 通信 |
| prom 文件存在但监控平台没数据 | exporter 没有读目录或 Prometheus 没抓取 | 配置对应 collector 和抓取目标 |
| 服务 active 但 collection_success 为 0 | 某模块采集或输出失败 | 查看具体 collection_error 或 scan_failed |
| collection_success 为 1 但仍有告警 | 采集成功地发现了异常 | 查 alert_count 和 alert 明细 |

持续缺失文件和必需进程会每轮告警，当前没有 YAML 可配置的告警冷却、静默或重复次数阈值。不要添加 `cooldown`、`ignore_missing`、`recursive`、`webhook`、`agent_ip` 等字段来期待新的功能：未支持字段会拒绝，其中 `agent_ip` 仅兼容读取旧配置并忽略，不能手工设置机器身份。

## 15 旧配置兼容字段

新部署使用本文前面的 `FilesMonitoring`、`ProcessMonitoring` 格式即可。旧 `md5`、`existence` 仍兼容，字段作用如下：

| 旧字段 | 用途 |
|---|---|
| `md5.enabled` | 开启旧文件 MD5 模块 |
| `md5.paths` | 要检查的文件或目录列表；启用时不能为空 |
| `md5.recursive` | 是否递归旧模块目录；默认 true |
| `md5.exclude_paths` | 兼容的排除路径及其后代；内部排除逻辑也会影响新 FilesMonitoring |
| `existence.enabled` | 开启旧路径存在性模块 |
| `existence.base_dir` | 相对文件规则的基础目录；启用时必填 |
| `existence.files` | 逐项配置 path 和 type；启用时至少一项 |
| `existence.files[].type` | `file`、`directory` 或 `any`，省略默认 file |

以下完整示例明确启用旧模块，并保留 setup 来使用固定输出：

```yaml
output_dir: /usr/local/anquan
state_file: state/md5.json
timezone: Asia/Shanghai

md5:
  enabled: true
  paths:
    - '/opt/app/config'
  recursive: true
  exclude_paths:
    - '/opt/app/config/cache'

existence:
  enabled: true
  base_dir: /opt/app
  files:
    - path: config/application.yaml
      type: file
    - path: data
      type: directory

login:
  enabled: false

server: []

setup:
  logs: '/var/log/时间anquan.log'
  prom: /var/lib/node_exporter/textfile_collector/process_monitor.prom
  interval_seconds: 300
```

出现任一新格式字段 `FilesMonitoring`、`ProcessMonitoring`、`server`、`setup`、`history` 时，旧 md5 和 existence 默认自动关闭；像示例这样明确 `enabled: true` 可以重新启用。若新旧文件模块同时检查同一范围，会分别扫描和记录，可能产生重复类型的检测结果。

`FilesMonitoring` 没有自己的 `exclude_paths` 子字段。兼容字段 `md5.exclude_paths` 被内部共用的排除逻辑读取，因此混用新旧模块时也可能排除新文件监控目标；旧 md5 启用时才会对其路径执行完整的归一化校验。新部署应优先直接配置需要的扫描范围，混用旧排除规则时核对实际范围。旧 existence 的相对 path 不允许用 `..` 逃离 base_dir，跨目录需求请用明确绝对路径。每次生产 Agent 启动也会重新建立旧 md5 的内容基线。

## 16 配置前的检查顺序

1. 确定每台机器的职责：需要的文件、必须的服务、成功登录、已有命令日志。
2. 在目标机器核对实际路径和完整进程命令；删除与该机器无关的演示规则。
3. 决定是否需要全机进程变化，再决定是否添加 Process。
4. 明确接收主控 UDP 地址；使用 history 时确认日志和全部接收端的入库确认能力。
5. 设置输出位置、巡检间隔和时区，保持登录和命令状态路径稳定。
6. 页面下发到目标节点，等待已应用，再按日志、主控事件和实际通知逐项验收。

运行与字段依据见 [配置解析](../internal/audit/config.go)、[文件规则](../internal/audit/files_monitor.go)、[进程规则](../internal/audit/process_monitor.go)、[成功登录采集](../internal/audit/ssh_login.go)、[操作命令采集](../internal/audit/history.go)、[常驻服务](../internal/audit/service.go) 和 [配置下发](../internal/audit/config_delivery.go)。更多部署命令见[部署调试与测试命令手册](部署调试与测试命令手册.md)，对接字段见 [Agent Master 协议](agent-master-protocol.md)。
