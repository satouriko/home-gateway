# Home Gateway

[![Checks](https://github.com/satouriko/home-gateway/actions/workflows/check.yml/badge.svg)](https://github.com/satouriko/home-gateway/actions/workflows/check.yml)

基于 Mihomo 与 DeepSeek Harness 的树莓派家庭网关：程序持续检测和处理明确故障，AI 负责诊断、独立复核和维护工具；用户通过聊天表达需求。

An AI-assisted home gateway with deterministic monitoring, guarded repairs, and versioned operator tools.

本仓库维护已部署的程序、用户偏好及恢复工具。当前配置对应现有家庭网络；它不是适用于所有路由器的通用安装发行版。

## 代码结构

```text
src/operator/       运维代理、发布器、程序巡检和保护机制
src/gateway/        网关网络配置和节点维护
src/dsh/            DSH 插件、身份说明与方法 skill
src/maintained/     DeepSeek 正式发布的诊断与工具源码
config/             DNS、分流模板、DSH profile 和资源偏好
preferences/        当前用户网络偏好和巡检计划
runtime/dsh/        DSH 的 npm 依赖与锁文件
deploy/             systemd、命令入口和日志容量配置
tests/              备份恢复、运维回归与维护程序测试
docs/               运维背景、接口与上游维护说明
snapshot/           导出版本与文件校验清单
```

开发流程见 [CONTRIBUTING.md](CONTRIBUTING.md)，上游兼容性见 [docs/UPSTREAM.md](docs/UPSTREAM.md)。

## 备份范围

- DSH 运维插件、局域网访问与中文界面补丁、身份说明、方法 skill、Web/headless profile。
- 受保护的网关与运维程序、systemd 服务和资源限制。
- DeepSeek 正式发布的诊断分析程序、工具源码，以及工作区中的测试源码。
- 用户分流、地区与故障节点筛选偏好，DNS 配置，巡检频率与预算、定价时段和存储限制。
- npm 依赖锁文件，以及 Mihomo 版本与校验值。

不保存 API key、订阅链接及其主机名、节点内容或密码、浏览器登录信息、SSH 私钥、Wi-Fi 密码、对话、日志、诊断样本、任务运行历史或未发布的候选代码。恢复时重新提供订阅链接与模型 API key，其他本机控制密钥重新生成。

`backup.SOURCE_MAP` 明确源码与系统安装路径的对应关系；`src/maintained/` 保存正式发布的维护程序；`preferences/` 保存偏好；`config/mihomo.template.json` 中的凭据已替换为占位符。`snapshot/manifest.json` 记录内容校验与文件权限。

## 自动同步

程序维护、正式部署与偏好统一提交到 `main`。同步会检查远端历史；存在冲突或未部署的远端程序变更时停止，不强推覆盖。当前同步结果直接提供给 DeepSeek 的实时上下文。

树莓派上的 `home-gateway-backup.timer` 每轮结束约 15 分钟后重新采集。程序会避开尚未验收的网络变更，检查敏感内容；只有内容变化时才提交，失败的推送会在下一轮重试。没有模型调用。GitHub 写权限由只针对本仓库的 deploy key 提供，密钥留在机器上，不进入备份。

系统保护和源代码在 `backup.py`、`install_backup.py`；公开仓库不会自动把远端代码下载到运行中的网关执行。备份过程不改变客户端的网关、DNS 或代理设置。

## 恢复

目标是干净的 Debian 13 ARM64 树莓派。先让替换机器通过现有华为路由器正常联网，并将它配置为快照中的 LAN 地址。凭据与无线接入信息需要重新提供。安装过程要能访问 Debian、Node.js、npm 与 GitHub 的软件下载地址。

先取得最新部署分支：

```sh
git clone --branch main https://github.com/satouriko/home-gateway.git
cd home-gateway
```

用权限为 `0600` 的临时 JSON 文件提供 `subscription_url`、`deepseek_api_key` 两个字段。这个文件应放在仓库目录之外。也可以通过标准输入传入，使用 `--credentials-file -`；不把密钥写在命令参数中。

先还原到一个不存在或为空的目录进行检查：

```sh
python3 restore.py --stage /var/tmp/gateway-restored --credentials-file /secure/path/credentials.json
```

在替换树莓派上安装程序和运行依赖：

```sh
sudo python3 restore.py --apply --credentials-file /secure/path/credentials.json
sudo reboot
sudo python3 restore.py --start
```

`--apply` 拒绝覆盖已有部署。它按 npm 锁文件安装 DSH，安装快照指定的 Node.js 与 Mihomo，重建专用用户、权限、独立控制路径和已知配置。GeoSite/GeoIP 从既有公开来源重新下载。启动前验证 Mihomo 配置，随后进行实际 DNS/HTTPS 诊断。

对话和任务历史会从空白开始。自动 GitHub 备份需要为替换机器重新授权一个只针对本仓库的 deploy key，再运行 `install_backup.py`；旧机器的推送密钥没有被备份。

## 验证

使用 Python 3.12/3.13 和 Node.js 24：

```sh
python3 -m pip install -r requirements-dev.txt
make check
```

检查不需要 root，不改变网络，也不调用模型 API。

测试覆盖凭据剔除、敏感内容拒绝、允许清单与符号链接、正式版本变更、重复导出、快照校验以及空目录恢复。空目录恢复已经验证；完整系统安装与启动仍需在替换卡或独立测试机器上演练，不能把目录还原等同于整机恢复通过。

上游 DSH 与 Mihomo 由其各自项目分发；本仓库记录本地扩展、配置与依赖，不打包上游完整安装目录。

## 许可

本仓库代码使用 [MIT](LICENSE) 许可。DSH、Mihomo、Node.js 及依赖按各自的上游许可分发，见 [上游维护](docs/UPSTREAM.md)。
