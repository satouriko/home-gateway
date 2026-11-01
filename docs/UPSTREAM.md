# 上游与兼容性

| 组件 | 当前基线 | 来源 | 本地扩展方式 |
|---|---|---|---|
| DeepSeek Harness | 0.2.1-rc.5，npm lock 固定依赖 | [deepseek-ai/deepseek-harness](https://github.com/deepseek-ai/deepseek-harness) | 独立插件、profile patch、方法 skill |
| Mihomo | 1.19.33，manifest 保存二进制校验值 | [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) | 独立配置、节点维护与网络程序 |
| Node.js | 24.14.1 | [Node.js](https://nodejs.org/) | 上游发行包，安装时校验 SHA256 |

DSH 依赖位于 `runtime/dsh/package-lock.json`。上游完整安装目录不进入本仓库。本仓库代码采用 MIT；运行依赖仍适用各自的许可证：DSH 为 MIT，Mihomo 1.19.33 为 GPL-3.0（以该发布标签的 LICENSE 为准），Node.js 及 npm 依赖按各自分发许可处理。

## 跟进上游

1. 在独立分支记录当前部署版本，阅读目标版本的变更和兼容要求。先更新依赖与适配代码，保留清晰的上游基线。
2. 优先使用稳定的插件接口和 profile patch。必须修改上游源码时，独立保存补丁与对应提交，不将修改混进 npm 安装产物后丢失来源。
3. 在隔离 profile 或测试机器上验证：插件加载、中文与 LAN 访问、浏览器会话、工具注册和持久化，以及诊断、发布和回退。
4. 网关相关升级另测 DNS、直连与代理路径、地区选择和维护者自己的 API 通路。通过测试才部署；保留上一版依赖和配置。
5. 更新实际版本记录、测试与兼容说明。仅更新版本号或依赖安装成功，不表示升级验收通过。

社区插件也按相同方式记录来源、锁定版本和测试。新增插件不能直接修改凭据、受保护的启动配置或恢复程序；前端适配要覆盖手机、平板与桌面。
