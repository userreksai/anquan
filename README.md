# Anqu：文件与登录巡检（v0.2.0）

按配置执行一次巡检：计算文件 MD5 并记录变化、读取最近一条登录记录、检查清单中的文件或目录。每次生成 JSON 汇总和 Prometheus / node_exporter Textfile Collector 格式的 `.prom` 文件。

完整需求及功能边界见 [需求与实现说明](docs/需求与实现说明.md)。目标运行环境为 Linux。所有设置及文件检查清单合并在一个 `config.yaml` 中，支持中文注释；YAML 解析使用 `go.yaml.in/yaml/v3`，构建时由 Go 自动下载依赖。

## 1. 编译和试跑

需要 Go 1.22 或更新版本。在项目根目录执行：

```sh
go test ./...
go vet ./...
go build -trimpath -o anqu ./cmd/anqu
./anqu -config demo/config.yaml -check-config
./anqu -config demo/config.yaml
```

演示配置使用项目内的测试文件与模拟 JSONL 登录记录，不读取本机系统登录日志。生成文件位于 `demo/output/`。修改 `demo/watched/app.conf` 后再次运行，即可看到 `modified` 记录；再运行一次，变化数归零，累计变更数保留。

从 Windows/macOS 交叉编译 Linux 程序（以下为 Linux shell 写法；PowerShell 用 `$env:GOOS='linux'` 等设置）：

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o anqu-linux-amd64 ./cmd/anqu
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o anqu-linux-arm64 ./cmd/anqu
```

## 2. 安装到 Linux

先解压对应架构的发布包并进入其目录（例如 `tar -xzf anqu-v0.2.0-linux-amd64.tar.gz`，然后 `cd linux-amd64`），将程序和配置放入约定目录。下面也适用于从源码编译后的目录：

```sh
sudo install -d -m 0755 /usr/local/anqu
sudo install -m 0755 anqu /usr/local/anqu/anqu
sudo install -m 0640 configs/config.example.yaml /usr/local/anqu/config.yaml
```

**修改 `config.yaml` 为真实路径，再执行：**

```sh
sudo /usr/local/anqu/anqu -config /usr/local/anqu/config.yaml -check-config
sudo /usr/local/anqu/anqu -config /usr/local/anqu/config.yaml
```

示例包含 `/etc/crontab`，目标主机没有该文件时请替换为真实监控文件；首次 MD5 扫描的配置路径不存在会报错。`-check-config` 检查配置结构、时区、路径规则与清单格式，不提前执行 MD5 或读取登录数据。

## 3. 配置说明

默认读取 `/usr/local/anqu/config.yaml`，也支持 `.yml` 后缀。配置采用 UTF-8 YAML，支持 UTF-8 BOM 和 `# 中文注释`；使用空格缩进，不用 Tab。未知字段、重复字段、多个 YAML 文档及错误的清单格式都会报错。三个采集模块可各自设置 `enabled: false`。完整带中文注释的模板见 [config.example.yaml](configs/config.example.yaml)。

| 字段 | 作用 / 默认值 |
|---|---|
| `output_dir` | 汇总输出目录，默认 `/usr/local/anqu` |
| `state_file` | MD5 基线和累计计数，默认 `state/md5.json`；相对路径以 `output_dir` 为基准 |
| `timezone` | 报告、文件名和登录时间的显示时区，默认 `Asia/Shanghai` |
| `md5.paths` | 文件或目录列表；开启该模块时必填 |
| `md5.recursive` | 是否扫描目录的全部子目录，默认 `true` |
| `md5.exclude_paths` | 要排除的完整路径；目录会连同子目录排除，不是 glob 通配符 |
| `login.source` | `wtmp`（默认）或 `jsonl` |
| `login.path` | 登录数据路径，默认 `/var/log/wtmp` |
| `login.last_command` | `wtmp` 模式使用的 util-linux `last` 命令，默认 `last`；可以填写可执行文件绝对路径 |
| `login.timeout_seconds` | `last` 超时，默认 10 秒，允许 1–3600 |
| `login.max_records` | `last` 最多读取的最近记录数量，默认 1000，允许 1–100000 |
| `existence.files` | 直接在主配置中填写文件检查清单，每项包含 `path`、`type` |
| `existence.base_dir` | 清单里相对路径的起始目录 |

除 `state_file` 和清单内路径外，配置里的相对路径均相对于 **config.yaml 所在目录**；不依赖运行时当前目录。`last_command` 为程序名时按进程 PATH 查找，不经过 shell，也不展开 `$变量`、`~` 或通配符。生产建议填写绝对路径。

合并在主配置里的文件检查清单示例：

```yaml
existence:
  enabled: true
  base_dir: /etc
  files:
    - path: ssh/sshd_config
      type: file
    - path: ssh
      type: directory
    - path: /opt/app/config.yaml
      type: file
```

当 `base_dir` 是 `/etc` 时，前两项对应 `/etc/ssh/sshd_config`、`/etc/ssh`；绝对路径直接使用。`type` 支持 `file`、`directory`、`any`，省略默认为 `file`。不允许重复路径和通过 `../` 越过 `base_dir` 的相对路径；目录以外的检查对象请明确写绝对路径。

启用存在检查时，`existence.files` 至少要有一项；不使用此功能时设置 `existence.enabled: false`。在 `files` 清单中添加文件不会自动加入 MD5 监控，内容变化检查由 `md5.paths` 控制。

### 从 v0.1.0 的两个 JSON 配置迁移

1. 拉取新版源码并重新编译，或下载 v0.2.0 的程序；旧版程序不能直接读取 YAML。
2. 参考 YAML 模板，把旧 `config.json` 中的各项实际值保留，将 `files.json` 中的条目移入 `existence.files`，删除 `existence.list_file`。
3. 把文件保存为 `/usr/local/anqu/config.yaml`，使用新版程序执行 `-config /usr/local/anqu/config.yaml -check-config`。
4. 更新 systemd 单元的 `ExecStart`，将配置路径改为 `/usr/local/anqu/config.yaml`，执行 `systemctl daemon-reload` 后启动任务。

只改变配置格式、保持实际 MD5 路径/排除/递归设置和输出/基线位置不变时，会沿用旧 MD5 基线，不要删除 `state/md5.json`。旧 JSON 文件可以留作备份。升级操作命令见 [需求与实现说明](docs/需求与实现说明.md)。

兼容过渡期间仍可显式执行 `anqu -config /usr/local/anqu/config.json` 使用旧版 JSON + `existence.list_file`。`existence.files` 和 `existence.list_file` 不允许同时配置。默认配置路径已经改为 `.yaml`，不自动回退到旧 JSON。

## 4. MD5 判定规则

- 首次完整扫描建立基线，不把现有文件当作新增。
- 之后与**上一次成功完成的 MD5 扫描**比较，记录 `added`、`modified`、`deleted`，包含文件路径、原 MD5、新 MD5。
- 每次成功扫描后更新基线。其他模块失败不阻止成功的 MD5 模块更新基线。
- 任一 MD5 读取失败、扫描中发现文件发生变化、基线损坏或扫描范围改变，本轮 MD5 标记失败，保留旧基线，不输出误导性的零变化指标。
- 已建立基线的监控路径消失，会记录 `missing_roots`，原有文件记录为删除。挂载目录临时不可用也可能表现为删除，需要结合挂载状态判断。
- 按文件内容判断；仅权限、属主、时间戳变化，不算 MD5 内容变化。重命名按删除旧文件和新增新文件处理。
- 跳过符号链接、设备、管道等非普通文件，汇总跳过数量；不递归进入符号链接目录。输出目录、基线和锁自动排除。

修改监控路径、排除路径、递归选项或输出/状态位置后，旧基线的扫描范围不再匹配，程序会报错。请停止定时任务，将旧状态文件改名备份，然后运行以建立新基线。例如：

```sh
sudo systemctl stop anqu.timer
sudo systemctl stop anqu.service
sudo mv /usr/local/anqu/state/md5.json /usr/local/anqu/state/md5.backup.json
sudo /usr/local/anqu/anqu -config /usr/local/anqu/config.yaml
sudo systemctl start anqu.timer
```

重新建立基线会重置累计变化计数。MD5 按本次需求用于内容变化检查；它不是数字签名或防碰撞的可信证明。第一版不提供经人工批准后才更新的固定可信基线模式。

## 5. 登录记录

### wtmp：默认方式

程序执行：

```sh
last -w -i --time-format iso -n 1000 -f /var/log/wtmp
```

使用 util-linux 版本的 `last`，从最近记录开始，跳过重启等系统记录，取第一条用户登录记录，输出 `source_ip`、`login_time`、`user`、`terminal`。命令输出强制使用英文和 UTC，再转换成配置时区。IPv4、IPv6 均支持；本地登录或未记录 IP 时 `source_ip` 为空。

目标系统必须实际写入 wtmp，且安装支持上述参数的 `last`；BusyBox/GNU acct/wtmpdb 等其他实现不保证兼容。只检查配置的一个 wtmp 文件和最近 `max_records` 条，不合并轮转文件。找到零条用户记录时输出 `record: null`、`anqu_login_found 0`；读取失败会标记错误。

wtmp 反映的是系统记录的登录会话，通常能提供终端。没有分配终端的 SSH 命令等可能不写入 wtmp；如果需要覆盖它们，应由登录采集端写 JSONL。

### JSONL：自定义登录日志

把 `login.source` 改成 `jsonl`，`login.path` 改为实际文件，例如 `/var/log/anqu-login.jsonl`。每行一个 JSON 对象：

```json
{"source_ip":"192.0.2.10","login_time":"2026-10-01T10:00:00+08:00","user":"ops","terminal":"pts/0"}
```

`login_time` 必须是含时区的 RFC3339 时间；无分配终端时使用 `"terminal":"N/A"`；本地登录的 IP 可以为空字符串。日志应只包含成功登录记录。程序顺序读取整个文件，按登录时间选择最新的一条，而非假设最后一行最新；同一时刻以靠后的记录为准。空行忽略，每行最多 1 MiB。无效记录会使该模块失败，不把旧记录冒充最近登录；文件较大时应由外部日志轮转限制大小。

附件 `anquan.sh.txt` 的原日志仅有时间、User、IP、Host，未写入终端，而且部分 IP 会被白名单过滤，因此无法从原文件完整恢复所有登录及终端。本版不直接解析该脚本旧日志，也不安装 SSH 登录钩子。可用 wtmp，或让现有登录采集端按上面的 JSONL 格式写入。

## 6. 输出与 node_exporter

每次执行，无论是否发现变化，都生成汇总。默认目录结构：

```text
/usr/local/anqu/
├── anqu
├── config.yaml                       # 主配置和存在检查清单合并在这里
├── 20261001_100000.123456789+0800.json  # 按时间命名的完整汇总
├── 20261001_100000.123456789+0800.prom  # 同一轮的指标归档
├── state/
│   ├── md5.json                      # 上次成功扫描的 MD5 与累计计数
│   └── md5.json.lock                 # Linux flock 锁文件，保留文件是正常的
└── textfile/
    └── anqu.prom                    # 最新一轮，供 node_exporter 读取
```

JSON 内 `collection_success` 表示采集是否完成，不代表没有异常：文件变化、文件缺失或类型不匹配仍是有效采集结果。三个模块各有 `enabled`、`success` 和详细数据；错误放在 `errors` 数组中。

给现有 node_exporter 增加参数：

```sh
--collector.textfile.directory=/usr/local/anqu/textfile
```

**必须指向 `textfile` 子目录，不要直接采集 `/usr/local/anqu` 内的历史 `.prom` 文件**，否则不同批次的同名指标会重复。程序先写同目录临时文件，再替换最终文件；`.prom` 不使用样本时间戳第三列，时间采用普通指标数值。这遵循 [node_exporter Textfile Collector 说明](https://github.com/prometheus/node_exporter/blob/master/README.md#textfile-collector)。

JSON 报告默认权限 0640，基线 0600，指标 0644，程序新建的输出目录 0755；请确保现有父目录也允许 node_exporter 用户访问。

| 指标 | 含义 |
|---|---|
| `anqu_collection_success` | 全部启用模块本轮是否采集成功，1/0 |
| `anqu_run_timestamp_seconds` | 最近一轮采集时间，Unix 秒 |
| `anqu_run_duration_seconds` | 采集耗时，不含文件输出时间 |
| `anqu_module_enabled{module}` / `anqu_module_success{module}` | 模块开启和成功状态 |
| `anqu_collection_errors` | 本轮错误数量 |
| `anqu_md5_files` / `anqu_md5_skipped` | 哈希文件数 / 跳过的非普通文件数 |
| `anqu_md5_missing_roots` | 已建基线后消失的配置路径数 |
| `anqu_md5_baseline_created` | 本轮是否建立初始基线 |
| `anqu_md5_changes{kind}` | 本轮新增、修改、删除数量 |
| `anqu_md5_changes_total{kind}` | 持久化累计变化数，重建基线时重置 |
| `anqu_md5_last_change_timestamp_seconds` | 最近发现变化的时间，没有变化时为 0 |
| `anqu_md5_file_change{path,kind}` | 本轮变化的文件明细，值为 1 |
| `anqu_login_found` | 当前数据源是否找到用户登录记录 |
| `anqu_last_login_timestamp_seconds` | 最近一次登录时间，Unix 秒 |
| `anqu_last_login_info{user,source_ip,terminal}` | 最近一次登录信息，值为 1 |
| `anqu_existence_checked` / `anqu_existence_missing` / `anqu_existence_type_mismatch` | 检查数 / 缺失数 / 类型不符数 |
| `anqu_file_check_success{path,type}` | 单个检查能否完成 |
| `anqu_file_exists{path,type}` | 是否存在，1/0；不可读时不输出此样本 |
| `anqu_file_matches{path,type}` | 是否存在且类型符合，1/0 |

MD5 或登录模块失败时，省略该模块的结果指标，保留失败状态；禁用模块通过 `anqu_module_enabled=0` 区分。文件检查部分失败时仍保留其他文件的有效结果。

PromQL 示例（示例采用五分钟运行一次）：

```promql
# 采集失败
anqu_collection_success == 0

# 超过十五分钟没有更新；首次尚未生成指标时还需配置 absent 告警
time() - anqu_run_timestamp_seconds > 900

# 最近十分钟观察到文件变化：即使某一轮本轮变化数被覆盖，累计计数仍可保留信息
sum by (instance) (increase(anqu_md5_changes_total[10m])) > 0

# 清单中的文件/目录缺失或类型不符
anqu_file_matches == 0
```

累计计数反映定时扫描观察到的变化，不能发现两次扫描之间修改后又恢复的瞬时变化。发生时间和前后 MD5 以归档 JSON 为准。

## 7. 定时运行和退出码

安装随附 systemd 单元：

```sh
sudo install -m 0644 deploy/anqu.service /etc/systemd/system/anqu.service
sudo install -m 0644 deploy/anqu.timer /etc/systemd/system/anqu.timer
sudo systemctl daemon-reload
sudo systemctl enable --now anqu.timer
sudo systemctl start anqu.service
sudo systemctl status anqu.timer
journalctl -u anqu.service --no-pager -n 30
```

默认开机一分钟后执行，之后每次执行结束五分钟后再执行；`systemd` 的时间精度设置可能带来少量延迟。每轮重读同一个 YAML 配置及其中清单，修改配置后下轮生效。执行周期由 timer 控制，不在 YAML 中设置。也可以自行用 cron 定时调用，二者选一个即可。

| 退出码 | 含义 |
|---|---|
| `0` | 采集成功，无变化或清单异常；首次正常建立基线也为 0 |
| `1` | 命令行参数、配置、采集、基线、锁或输出错误 |
| `2` | 正常完成采集，但发现 MD5 变化、文件缺失或类型不匹配 |

systemd 已设置 `SuccessExitStatus=2`，避免把有效的异常发现当作服务执行失败。Linux 使用非阻塞文件锁避免相同基线的任务并发；进程退出自动释放锁，不要删除正在使用的锁文件。非 Linux 仅供开发演示，使用目录锁；异常退出后需确认没有在运行的进程，再手动清理对应锁目录。

报告全部发布完成后才提交 MD5 基线。多个文件不是一次事务：如果程序在发布与提交之间崩溃，下次可能重复记录同一变化，以保留信息为优先。输出目录或配置本身不可用时可能无法生成新错误指标，请同时监控进程退出、任务日志和指标更新时间。

程序保留全部历史报告，不自动删除；请按实际保留周期安排归档。一个输出目录和一份基线用于一个配置实例，避免不同配置共用最新指标文件。

## 8. 验证范围

测试覆盖首次建基线、内容 MD5 已知值、连续扫描、增删改、递归和排除、自身输出排除、基线损坏/范围变化、输出失败保留基线、整个监控路径消失、清单缺失与类型不符、IPv4/IPv6/本地登录、JSONL 时间排序和坏数据、`last` 输出解析、指标标签转义、模块隔离和并发锁。另覆盖单个 YAML 独立运行、中文注释、默认值、清单修改生效、YAML 严格校验及 JSON 转 YAML 保留基线。

交付构建与测试结果见发布包中的 `BUILD-INFO.txt`。实际 Linux 主机的 wtmp/last 兼容性、systemd 执行及 node_exporter 抓取仍需在目标环境验收。

登录工具参数依据：[util-linux last 手册](https://man7.org/linux/man-pages/man1/last.1%40%40util-linux.html)。
