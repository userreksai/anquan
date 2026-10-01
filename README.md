# Anqu：文件与登录巡检（v0.3.0）

按配置执行一次巡检：计算文件 MD5 并记录变化、读取最近一条登录记录、检查清单中的文件或目录。每次生成 JSON 汇总和 Prometheus / node_exporter Textfile Collector 格式的 `.prom` 文件。

目标运行环境为 Linux。**A 服务器保留 YAML 和源码，构建时加密内置配置；B/C 节点只接收并运行生成的程序，不读取外部配置文件。** 修改 YAML 后重新构建，可用于另一台或一组路径相同的节点。JSON 配置和独立文件清单入口已取消，JSON 报告、JSON 基线与 JSONL 登录日志保留。

配置加密采用 AES-256-GCM，每次构建生成随机密钥和 nonce；构建时去除 Go 调试符号和构建路径。这样减少配置明文直接暴露，但**不能保证无法反编译或提取配置**：独立程序必须能自行解密，有 root 权限或能分析程序/内存的人仍可能恢复信息。按本次需求，报告和指标继续保留真实路径，基线也包含监控路径。完整功能边界见 [需求与实现说明](docs/需求与实现说明.md)。

## 1. A 服务器：配置并构建

需要 Git、Go 1.22 或更新版本。首次构建会由 Go 下载 YAML 解析依赖。在 A 上执行：

```sh
git clone https://github.com/userreksai/anquan.git
cd anquan

# 仅首次复制模板；已有 config.yaml 时不覆盖
if [ ! -e config.yaml ]; then
  cp configs/config.example.yaml config.yaml
fi
chmod 0600 config.yaml
vi config.yaml

go test ./...
go vet ./...

# 默认读取运行构建命令时当前目录下的 config.yaml
go run ./cmd/anqu-build -output ./dist/anqu-linux-amd64 -goos linux -goarch amd64

# ARM64 节点改用以下命令
go run ./cmd/anqu-build -output ./dist/anqu-linux-arm64 -goos linux -goarch arm64
```

模板内填写的是 **B/C 节点上的路径**，不是 A 的路径。构建工具严格校验配置结构、时区、路径规则和清单格式，不要求 A 存在这些被监控文件，也不提前执行巡检。示例中的 `/etc/crontab` 在目标节点不存在时请替换或移除。

构建工具参数：

| 参数 | 用途 |
|---|---|
| `-config` | YAML 输入路径，默认当前工作目录的 `config.yaml`；支持 `.yaml` / `.yml` |
| `-output` | 生成的节点程序路径，例如 `./dist/anqu-linux-amd64` |
| `-goos` | 目标系统，默认 `linux` |
| `-goarch` | 目标 CPU 架构，默认构建工具所在主机架构；建议显式指定 `amd64` 或 `arm64` |
| `-go` | 用于编译的 Go 可执行文件，默认 `go` |

构建工具通过 Go overlay 内置加密数据，临时目录不保存配置明文；使用独立的临时 Go 构建缓存并在结束后清理。A 上的原始 YAML 仍保留，供以后修改。私有 `config.yaml` / `config.yml` 已加入根目录 `.gitignore`，不要提交真实配置或将其放进节点发布包。

发布包只提供源码和构建工具，不提供含通用真实配置的节点程序。使用构建工具包时，仍需在 A 安装 Go，进入随包源码根目录，准备 `config.yaml` 后运行 `./anqu-build -output ./dist/anqu-linux-amd64 -goos linux -goarch amd64`。普通 `go build ./cmd/anqu` 不会嵌入配置，生成物不能用于巡检。

演示（以下适用于 Linux amd64）：

```sh
go run ./cmd/anqu-build -config ./demo/config.yaml -output ./demo/anqu -goos linux -goarch amd64
./demo/anqu
```

程序所在目录为 `demo`，因此读取该目录内的测试文件与模拟 JSONL 登录记录，结果位于 `demo/output/`。修改 `demo/watched/app.conf` 后再运行，可看到 `modified`；再运行一次，本轮变化数归零，累计变化数保留。默认运行不打印摘要，用报告和退出码查看结果。

## 2. B/C 节点：只部署程序

将 A 构建的对应架构程序传到节点。可以同时传入 `deploy/anqu.service`、`deploy/anqu.timer` 用于定时执行；**不用传 YAML、源码或构建工具**。假定程序已放在节点当前目录：

```sh
sudo install -d -m 0755 /usr/local/anqu
sudo install -m 0700 ./anqu-linux-amd64 /usr/local/anqu/anqu
sudo /usr/local/anqu/anqu
echo $?
```

节点程序只提供 `-help` 和 `-version`，没有 `-config`、`-check-config` 或导出配置命令，不读取旁边的 YAML/JSON，也不会输出完整配置。巡检完成默认安静退出，查看本轮 JSON、指标和退出码；采集或输出故障仍应结合任务日志排查。生成的节点程序默认权限 0700，仅所有者可读写执行；按上述命令由 root 安装后由 root 任务运行，这不限制 root 自身的检查能力。

需要给 C 使用时，在 A 修改 `config.yaml`，重新执行构建并下发新的程序；路径相同、架构兼容的节点也可以共用同一构建。目标节点不需要安装 Go；wtmp 模式仍需要兼容的 util-linux `last`。

旧版本升级及节点遗留配置清理步骤见 [升级说明](docs/需求与实现说明.md#七已有服务器升级到内置配置)。

## 3. A 上的 YAML 配置说明

构建时默认读取当前工作目录的 `config.yaml`，也可用 `-config` 指定其他 YAML。配置采用 UTF-8，支持 BOM 和 `# 中文注释`；使用空格缩进，不用 Tab。未知字段、重复字段、多个 YAML 文档及错误清单会导致构建失败；不接受 JSON 配置和 `existence.list_file`。三个模块可分别设置 `enabled: false`。中文模板见 [config.example.yaml](configs/config.example.yaml)。

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

除 `state_file` 和清单内路径外，配置里的相对路径均相对于 **B/C 节点可执行程序所在目录**，不依赖 A 的构建路径或 B/C 启动命令时所在目录。`state_file` 相对于 `output_dir`，清单项相对于 `existence.base_dir`；绝对路径直接使用。`last_command` 为程序名时按进程 PATH 查找，不经过 shell，也不展开 `$变量`、`~` 或通配符。生产建议填写绝对路径。

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

旧配置应迁移到 A 的 YAML；把旧 `files.json` 条目移入 `existence.files`，删除 `existence.list_file`。保持实际 MD5 路径、排除、递归和输出/基线位置不变时可复用旧基线，不要删除 `state/md5.json`。从旧版本迁移相对路径时注意基准目录的变化，必要时改为绝对路径。配置变更必须重新构建并替换节点程序。

## 4. MD5 判定规则

- 首次完整扫描建立基线，不把现有文件当作新增。
- 之后与**上一次成功完成的 MD5 扫描**比较，记录 `added`、`modified`、`deleted`，包含文件路径、原 MD5、新 MD5。
- 每次成功扫描后更新基线。其他模块失败不阻止成功的 MD5 模块更新基线。
- 任一 MD5 读取失败、扫描中发现文件发生变化、基线损坏或扫描范围改变，本轮 MD5 标记失败，保留旧基线，不输出误导性的零变化指标。
- 已建立基线的监控路径消失，会记录 `missing_roots`，原有文件记录为删除。挂载目录临时不可用也可能表现为删除，需要结合挂载状态判断。
- 按文件内容判断；仅权限、属主、时间戳变化，不算 MD5 内容变化。重命名按删除旧文件和新增新文件处理。
- 跳过符号链接、设备、管道等非普通文件，汇总跳过数量；不递归进入符号链接目录。输出目录、基线和锁自动排除。

在 A 修改监控路径、排除路径、递归选项或输出/状态位置并重新构建后，旧基线的扫描范围不再匹配，程序会报错。请停止定时任务、替换程序，将旧状态文件改名备份，然后运行以建立新基线。例如，以下在节点执行（新程序已传到当前目录）：

```sh
sudo systemctl stop anqu.timer
sudo systemctl stop anqu.service
sudo install -m 0700 ./anqu-linux-amd64 /usr/local/anqu/anqu
sudo mv /usr/local/anqu/state/md5.json /usr/local/anqu/state/md5.backup.json
sudo /usr/local/anqu/anqu
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
├── 20261001_100000.123456789+0800.json  # 按时间命名的完整汇总
├── 20261001_100000.123456789+0800.prom  # 同一轮的指标归档
├── state/
│   ├── md5.json                      # 上次成功扫描的 MD5 与累计计数
│   └── md5.json.lock                 # Linux flock 锁文件，保留文件是正常的
└── textfile/
    └── anqu.prom                    # 最新一轮，供 node_exporter 读取
```

JSON 内 `collection_success` 表示采集是否完成，不代表没有异常：文件变化、文件缺失或类型不匹配仍是有效采集结果。三个模块各有 `enabled`、`success` 和详细数据；错误放在 `errors` 数组中。

节点目录没有需要读取的 `config.yaml` 或 `files.json`。报告、指标和基线保留真实文件路径以便排查，这些输出并未加密。查看最近一次 MD5 变化（需要安装 `jq`）：

```sh
report=$(ls -1t /usr/local/anqu/[0-9]*.json | head -n 1)
jq '.md5.changes' "$report"
cat /usr/local/anqu/textfile/anqu.prom
```

成功扫描后基线会更新，下一轮未再次变动则变化数为 0；需要追溯时查看之前的时间命名 JSON。

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

默认开机一分钟后执行，之后每次执行结束五分钟后再执行；`systemd` 的时间精度设置可能带来少量延迟。每轮使用程序内置配置，不读取节点配置文件。执行周期由 timer 控制，不在 YAML 中设置。也可以自行用 cron 定时调用，二者选一个即可。附带服务设置 `LimitCORE=0`，减少意外生成 core dump，不能阻止 root 检查程序或内存。

| 退出码 | 含义 |
|---|---|
| `0` | 采集成功，无变化或清单异常；首次正常建立基线也为 0 |
| `1` | 命令行参数、配置、采集、基线、锁或输出错误 |
| `2` | 正常完成采集，但发现 MD5 变化、文件缺失或类型不匹配 |

systemd 已设置 `SuccessExitStatus=2`，避免把有效的异常发现当作服务执行失败。Linux 使用非阻塞文件锁避免相同基线的任务并发；进程退出自动释放锁，不要删除正在使用的锁文件。非 Linux 仅供开发演示，使用目录锁；异常退出后需确认没有在运行的进程，再手动清理对应锁目录。

报告全部发布完成后才提交 MD5 基线。多个文件不是一次事务：如果程序在发布与提交之间崩溃，下次可能重复记录同一变化，以保留信息为优先。输出目录不可用或内置配置加载失败时可能无法生成新错误指标，请同时监控进程退出、任务日志和指标更新时间。

程序保留全部历史报告，不自动删除；请按实际保留周期安排归档。一个输出目录和一份基线用于一个配置实例，避免不同配置共用最新指标文件。

## 8. 验证范围

已通过 34 个顶层测试及其子测试，覆盖 MD5 基线与增删改、递归/排除、输出失败、清单缺失/类型不符、登录解析、指标、模块隔离、并发锁、YAML 严格校验、拒绝 JSON 配置和旧清单入口、加密载荷完整性及节点相对路径。Windows 集成验证已确认：只复制程序即可运行、不读取旁边的配置文件、修改 A 的 YAML 重新构建后 C 使用新配置而 B 保持原配置。Linux amd64/arm64 节点程序和构建工具均已交叉编译通过。

交付构建与测试结果见发布包中的 `BUILD-INFO.txt`。实际 Linux 主机的 wtmp/last 兼容性、systemd 执行及 node_exporter 抓取仍需在目标环境验收。

登录工具参数依据：[util-linux last 手册](https://man7.org/linux/man-pages/man1/last.1%40%40util-linux.html)。
