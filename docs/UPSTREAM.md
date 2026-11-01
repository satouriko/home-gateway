# 上游与兼容性

| 组件 | 当前基线 | 来源 | 本地扩展方式 |
|---|---|---|---|
| DeepSeek Harness | 0.2.1-rc.5，npm lock 固定依赖 | [deepseek-ai/deepseek-harness](https://github.com/deepseek-ai/deepseek-harness) | 独立插件、profile patch、方法 skill |
| dsh-web-mobile | 3.2.1 | [mexiaosqwq/dsh-web-mobile](https://github.com/mexiaosqwq/dsh-web-mobile) | 客户端插件及独立手机样式、手势补丁 |
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


手机插件的 peer 范围不接纳当前 DSH 预发布版本。`runtime/dsh/package.json` 对该插件使用精确 peer overrides，保持已安装的 DSH 基线；普通 `npm ci` 能完整重建依赖，不使用 `--legacy-peer-deps`。命名 profile 通过受控链接引用同一套锁定依赖，恢复器核对版本后重建链接。

手机额外适配位于 `src/dsh/mobile-layout.mjs`，由原有中文/LAN 插件注入，不改 npm 安装产物。页面禁止手势缩放，文本字段至少16px，避免 iOS 聚焦自动放大；代码、长消息和工具栏需要分别验证，不能只检查空会话或 document.scrollWidth。Safari 浏览器自身的边缘历史导航并不完全受网页 CSS 控制，边缘拦截只能作用于页面收到的触摸事件。

## 原生独立执行扩展

`runtime/dsh/patches` 保存针对固定 npm 制品的 MIT 补丁、许可证、来源与前后哈希。它为调度器增加独立执行器和有界真实回执，为原生任务页增加执行状态、摘要及独立会话链接。普通会话提醒保持原语义。恢复安装在 npm ci 后调用 `tools/apply_dsh_patches.py`；依赖或哈希变化必须复核，不能强行套用旧补丁。

执行身份先持久化再调用外部执行器，重启重放使用同一身份；执行器未注册时保持待处理，不退回来源会话调用模型。原生历史仍使用原有条数/日期保留规则。升级源码应修改上游 TypeScript 模块和客户端组件后重新生成 Typert；目前公开仓库保存可重放的固定制品补丁，尚未声明已合并上游。

旧 SDK 不理解新增任务字段。回退必须停止 DSH 并同步恢复兼容的任务数据，不能只移除代码补丁，也不能用旧的完整会话目录覆盖新增用户聊天。

## 网络概览插件

`src/dsh/network-overview` 是独立的本地双侧插件。宿主从已登记的文件模块及最近 package.json 发现 `dsh.client` 声明，浏览器模块通过公开的 main/sidebar.panellist 插槽挂载；共享既有 React，不安装额外生产依赖，也不增加上游补丁。宿主在既有 Web 端口注册受 LAN 访问校验保护的只读接口，数据适配位于 `src/operator/overview.py`。插件程序与 profile 注册进入有限恢复快照，运行数据不进入公开备份。

网络观测、受保护双路径探测、编程沙箱启动器和同步回执均由本项目模块及原生插件组合实现；未新增 DSH SDK 源码补丁。原生通知通过会话维护锁或持久化写租约追加 notice，上游升级需运行真实 SDK 持久化测试。
