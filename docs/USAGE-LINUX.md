# Linux 使用指南

本文介绍在 Linux 上配置并运行 helm-x。配置文件操作使用 Go 的跨平台文件接口；Linux 构建和桌面打包也有对应任务。Linux 桌面构建依赖 GTK 4 与 WebKitGTK 6，具体包名因发行版而异。命令行模式不会打开桌面窗口，但预编译二进制仍可能链接这些运行库；遇到共享库错误时，按发行版安装项目包声明的运行依赖。

## 1. 准备 Codex 配置

先以日常运行 Codex 的用户运行一次 Codex，并确认配置文件存在：

```bash
ls -l ~/.codex/config.toml
```

helm-x 默认查找 `~/.codex/config.toml`，其次查找 `~/codex/config.toml`。也可以通过 `CODEX_HOME` 指定配置目录，但该目录中必须已经有 `config.toml`：

```bash
export CODEX_HOME="$HOME/.codex"
```

配置文件应包含激活的 provider，例如：

```toml
model_provider = "custom"

[model_providers.custom]
name = "Custom"
base_url = "https://your-api.example/v1"
wire_api = "responses"
api_key = "your-api-key"
```

如果已有配置，不要为了照抄示例而覆盖它；确认 `model_provider` 指向的 provider 表存在，并配置了可用的 `base_url`。

## 2. 获取并运行

如果项目发布页提供 Linux 版本，下载与本机架构相符的文件后，按发布说明安装或运行。若使用源码构建，请先安装该项目要求的 Go、Node.js/npm，以及 Linux 桌面构建依赖，然后在仓库根目录执行：

```bash
wails3 task build
```

Linux 原生构建需要 CGO 和 C 编译器。仓库的 Linux 桌面包依赖 GTK 4 与 WebKitGTK 6；如果只运行 CLI，仍应使用项目构建任务生成二进制，以确保构建标签和前端资产与当前配置一致。

确认二进制可执行后，可先运行自检：

```bash
./bin/helmx verify
```

若二进制已安装到 `PATH`，可将上面的 `./bin/helmx` 替换为 `helmx`。

## 3. 启动方式

推荐直接运行代理：

```bash
helmx proxy
```

默认监听 `127.0.0.1:1800`。代理会从 Codex 配置读取上游地址，将激活 provider 的 `base_url` 临时改到本地代理，并在正常按 `Ctrl+C` 停止时还原该地址。运行期间保持这个终端开启，再从另一个终端启动 Codex：

```bash
codex
```

如果本机 1800 端口已被占用，可为代理指定其它端口：

```bash
helmx proxy --listen 1801
```

代理启动时会把配置指向相应端口。需要自行设置端口或上游时，可查看：

```bash
helmx proxy --help
```

也可以拆开执行配置注入和代理启动：

```bash
helmx apply --listen 1800
helmx proxy
```

`helmx apply` **只修改 Codex 配置，不会启动代理**。如果只运行 `apply` 而代理没有启动，Codex 会尝试连接本机代理并可能报连接错误。日常使用优先采用单独运行 `helmx proxy` 的方式。

## 4. 验证配置

```bash
helmx verify
```

该命令运行本地自检。需要验证 Codex CLI 的端到端连接时，可运行：

```bash
helmx verify --e2e
```

端到端检查会实际调用 Codex，可能访问已配置的上游服务。代理运行时也可检查输出中的监听地址和上游地址，并查看 Codex 请求是否出现在 helm-x 控制台或日志中。

## 5. 停止、还原与移除

正常停止 `helmx proxy` 时按 `Ctrl+C`，程序会尝试把 `base_url` 还原为启动代理前的值。如果进程被强制结束或系统异常关机，可手动还原：

```bash
helmx proxy --restore
```

如需移除 helm-x 写入的上下文默认键并从完整备份恢复配置：

```bash
helmx remove
```

默认情况下，如果检测到备份比当前配置旧、恢复可能丢失后来新增的配置键，命令会拒绝覆盖并列出差异。先手工合并或备份当前文件，再决定是否使用 `--force`；该选项可能丢失备份之后增加的配置：

```bash
helmx remove --force
```

## 6. Linux 常见问题

### 提示找不到 Codex 配置

确认 Codex 已至少启动过一次，并检查默认文件或自定义目录：

```bash
ls -l ~/.codex/config.toml
printf 'CODEX_HOME=%s\n' "$CODEX_HOME"
```

`CODEX_HOME` 应指向包含 `config.toml` 的目录，而不是文件本身。若使用非标准目录，可在同一个终端中设置变量后再运行 helm-x：

```bash
export CODEX_HOME="$HOME/path/to/codex-config"
helmx verify
```

### 提示权限不足

以拥有该 Codex 配置的普通用户运行 helm-x，不要用 `sudo`。检查文件和目录的所有者及写权限：

```bash
id
ls -ld "$HOME/.codex"
ls -l "$HOME/.codex/config.toml"
```

若配置文件是之前用 `sudo` 创建的，先确认所有者后再修复归属；不要直接对整个家目录递归修改权限。

### Codex 无法连接本地代理

确认 `helmx proxy` 仍在运行，并且它显示的监听端口与 Codex 配置中的 `base_url` 端口一致。端口被占用时，使用 `--listen` 更换端口后重新启动代理。单独执行 `helmx apply` 不会启动监听服务。

### 提示 TOML 格式不支持

helm-x 为避免破坏用户文件，会拒绝写入当前解析器不支持的配置结构。不要手工删除不认识的配置项；先备份 `config.toml`，再检查报错内容并提交给项目维护者定位。

### 桌面窗口或命令无法启动

从终端启动并查看错误。若提示找不到共享库，安装与该构建版本匹配的 GTK 4 / WebKitGTK 6 运行库后重试。命令行子命令（如 `helmx proxy`、`helmx verify`、`helmx remove`）不会创建窗口；但预编译二进制若动态链接桌面库，启动 CLI 也需要这些运行库。

### Ubuntu 24.04 出现 `bwrap: setting up uid map: Permission denied`

这不是 Codex 配置注入错误。WebKitGTK 使用 `bwrap` 为网页渲染进程建立隔离环境；Ubuntu 24.04 的 AppArmor 会限制非特权应用创建 user namespace。若当前应用没有允许该操作的策略，`bwrap` 会因 UID 映射被拒绝，随后 WebKit 的 `dbus-proxy` 退出，桌面窗口可能以 `SIGTRAP` 结束。

先使用浏览器只读控制台绕过桌面 WebView：

```bash
./helmx ui
```

保持终端运行，并手动打开它打印的 `http://127.0.0.1:8090` 地址。这个降级控制台只读，不等同于完整桌面 GUI。

若要使用桌面窗口，优先让系统管理员为 `bwrap` 配置适当且范围有限的 AppArmor user-namespace 策略。若程序运行在 Docker、LXC、远程开发容器或受管机器里，还需由宿主机管理员检查外层 seccomp / AppArmor 限制；容器内部安装 GTK/WebKit 包不能解除宿主策略。

仅用于临时确认故障是否来自 WebKit 沙箱时，可以在当前进程禁用 WebKit 沙箱后试运行：

```bash
WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS=1 ./helmx
```

此变量会降低 WebKit 渲染进程的隔离保护，不建议作为长期启动方式，也不要在此模式下加载不可信网页内容。

## 文件位置

| 内容 | 默认位置 |
|---|---|
| Codex 配置 | `~/.codex/config.toml` |
| 注入前完整备份 | `~/.codex/config.toml.helmx-bak` |
| 代理地址还原点 | `~/.codex/config.toml.helmx-proxy-bak` |
| helm-x 运行配置 | `~/.helmx.config.json` |
| 代理日志 | `~/.codex/helmx.log` |
| 事件日志 | `~/.codex/helmx-cyber.log` |

设置 `CODEX_HOME` 后，Codex 配置、备份和日志会位于该目录，而不是默认的 `~/.codex`。
