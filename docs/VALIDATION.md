# 部署验证

## 手机与自动化接入

适配基线：DSH 0.2.1-rc.5、dsh-web-mobile 3.2.1、Node.js 24.14.1。

- `make check`：25 项备份/恢复及补丁测试、109 项运维回归、14 项 JavaScript 行为测试；含快照 SHA 校验和公开内容扫描。
- 空检查轮次：历史无输出状态行合并为程序检查卡片，展示真实检查、时间和未调用模型的原因；两个浏览器另测用户输入、工具操作和迟到回复不被隐藏。
- Playwright Chromium 与 WebKit：375、390、430、768 像素触屏视口，以及1280像素桌面。验证侧栏完全收起、遮罩抽屉不挤压正文、输入框与发送按钮在屏幕内、16px输入字号和固定页面比例。用已有长消息与 JSON 代码块复测，菜单与页签同一行；桌面保持原布局。
- 线上原生任务保持同一个 ID，以短周期验收一次程序拒绝后恢复四小时间隔。运行历史为 skipped，显示实际间隔保护原因；来源会话文件 SHA 和大小均保持不变。
- 线上原生运行记录页在 Chromium 与 WebKit 中显示独立执行标签、跳过结果和实际程序原因。
- 线上独立 headless 验收只查询一次 gateway(status)，CLI 成功退出、root 回执 completed、新会话可冷读归入同一工作区；进程退出后会话写锁可重新取得。验收标为 deployment_validation，不计入常规复核预算或程序信心。原生完成历史回写由实际 SDK 与程序测试覆盖。
- `npm ci --offline --ignore-scripts`：树莓派在独立 RAM 临时目录按锁文件重新安装621个包，保留所有基线依赖；不代表完整空白系统恢复已经验收。
- 局域网 IP 和域名均返回中文页面；部署期间未修改客户端网络设置，Mihomo 数据面未重启。

浏览器检查可以独立复现，不发送聊天、不访问模型：

```sh
npm ci --prefix tests/browser
npx --prefix tests/browser playwright install chromium webkit
MOBILE_URL=http://gateway-address npm --prefix tests/browser run check
npm --prefix tests/browser run inspection
```

要覆盖已有真实长对话，设置 `MOBILE_TEST_CONVERSATION` 为现有会话标题；检查只打开会话，不修改消息。截图默认写系统临时目录，可通过 `BROWSER_ARTIFACTS` 指定其他仓库外目录。依赖和截图不进入公开快照。

自动化浏览器没有复现实体 iPhone 的浏览器全部系统手势、旧标签页保存的缩放状态或软键盘动画。Safari 的系统级历史导航不保证由网页完全禁止；页面内非交互边缘的触摸拦截和原有抽屉按钮可降低误触。完整空白系统恢复仍需独立验收，现有结果不替代该验收。

固定 SDK 的独立执行扩展有19项实际模块/Cordis测试，覆盖六种时间规则、普通提醒兼容、来源会话隔离、持久化 pending、重启重放、超时、混合历史分页与保留、原生编辑和删除。安装验证与测试命令见 CI：npm ci 后执行哈希校验补丁，再通过 SDK_RUNTIME 指向安装目录运行 tests/dsh-execution。客户端历史另有八种浏览器状态/兼容场景验证。

## 只读网络概览

适配器测试覆盖实际入口链、provider节点、循环/缺项、规则与偏好不一致、业务拒绝、失效观测、部分损坏文件、敏感字段剔除与并发缓存。接口测试覆盖 GET、写方法拒绝、来源拒绝和异常信息不外泄。浏览器检查运行实际插件客户端与 React，覆盖完整长节点名、过期/离线状态、隐藏与退出停止刷新、并发刷新合并及手机/桌面尺寸；命令：`npm ci --prefix tests/browser && npm --prefix tests/browser run overview`。

概览读取现有健康观测，不测带宽，不强制探测，也不调用模型。健康URL通过不能替代具体业务验收。


家庭实际访问与持续维护：`PYTHONPATH=src/operator python3 -m unittest discover -s tests/operator -q` 覆盖来源排除、有限流量增量、失败去重、采集间断、容量淘汰、业务分层、独立路径、公平回执、发布验收及巡检上下文保留边界。`DSH_NATIVE_PACKAGE=/opt/dsh/package.json node --test tests/sync-notices.test.mjs` 使用实际原生持久化验证通知写锁、重启、取消和幂等。

实机验收使用独立 probe UID 路由与临时非 TUN 引擎，分别固定 DIRECT 和实际完整节点名；匿名请求返回407，不可用代理不回退直连。模拟 Web 服务监听权限的沙箱能够写工作区，拒绝写系统文件，无法读取凭据和控制socket。发布检查需要运行新操作本身；同一原生会话自动收到暂缓和最终远端回执，通知不调用模型。网页首页内容验证的结果仅适用于对应端点，不代表登录后的完整应用已验收。

流量记录是滚动72小时的有限元数据快照及拨号错误，主动探测被排除。它会遗漏采样间的短连接、未经过本机的流量及不可观测的应用行为；不能称为完整浏览历史、精确计费流量或人员身份。未解决的问题不会因为样本过期或一次合成探测成功自动改成已修复。
