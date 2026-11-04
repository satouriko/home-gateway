# 维护接口

实际可用工具与参数以工具目录为准，版本和源码位置从当前系统上下文获取。

## 用户网络偏好

gateway_policy 的 get 查询有效目标；test 用 preferences JSON 补丁验证候选；apply 才应用。apply 必须来源于本轮网页聊天中用户明确提出的新目标，后台维护进程没有此权限。发布前校验、90秒内实际验收，未通过由独立程序恢复此前配置和策略这一整对检查点。

字段：mode（rule/direct/global）；preferred_label、preferred_keywords（节点名字中的字面关键词数组，最多8项）；allow_other_regions、allow_proxy_direct_fallback、mainland_direct（布尔）；direct_domains、proxy_domains（域名后缀数组，各最多100项）；excluded_keywords（故障节点名字关键词数组）；adaptive_routes（精确域名到direct/proxy的映射）；routing_strategy（自动调整所需依据的布尔条件）。只修改用户本次要求的字段。工具返回实际生效的策略，不能只改文档或skill。地区池的内部US_AUTO/us标识是历史标识，以preferences内容确定真实地区。

routing_strategy 的 require_degraded_current、require_public_service_basis、require_route_conflict、allow_latency_only 是当前用户目标的一部分，不是永久方法常量。每轮读取有效值；后台不能自行放宽。显式后缀规则优先于自动精确规则，独立控制域名受保护；改变策略或规则会改变策略版本，使旧证据失效。

## 费用与调度

实时上下文 maintenance_pricing 返回北京时间的峰谷状态和规则来源。例行日志分析、复盘与改进由原生任务与程序准入延后到谷价窗口，并留出任务结束时间；新故障、故障复发和用户聊天不受此延后约束。未知法定节假日保守按普通工作日判断，已核实的日期单独加入定价配置。费用规则在独立配置中，不写死进方法skill。

## 巡检分析程序

候选 Python 文件定义 `inspect(snapshot)`。输入为真实诊断快照及近期 history；返回 `summary` 字符串、`action`（none/recheck_nodes/refresh_subscription）和最多三个 `probe_domains`。

这是纯数据分析函数，不导入模块、不访问文件或网络。支持基础容器、条件、循环、字典get/items和常见聚合函数。测试包括健康网络不建议操作、代理路径故障建议重新检测。建议仍受外围操作预算和当前用户策略约束。

通过 gateway_program 的 status 获取现有源码，test 验证，publish 激活。候选文件在工作区，source_path 指向它。运行失败恢复前版。

## 可维护运维工具

候选 Python 模块定义 `run(request)`，可以使用标准库维护自己的探测与解析逻辑。

- `self_test`：运行真实断言，返回 `{"ok":true,"capabilities":{"能力名":"说明"}}`。
- `inspect`：执行有界、只读观测，返回带 `observations` 列表的 JSON 对象。
- 其他 operation：模块自行定义，并在 capabilities 中说明。

通过 gateway_tools 读取现有源码、测试、发布、调用。测试和运行在独立的低权限沙箱中，主机只读、临时空间32MB、内存128MB、CPU和进程有上限、执行最长12秒。模块不能读取维护者的凭据，也不能直接修改正式网络；需要修复时返回证据与建议，由外层 Agent 调用受保护工具。Unix 操作代理也会按工作进程身份拒绝写操作。

测试应能复现解析、分类或工具缺陷；不得以恒定成功代替断言。更新时保留已有能力。发布前检查、发布后复测，运行异常自动恢复前版或禁用失败版本。

## 方法 skill

可编辑源码在系统上下文的 skill_source，正式副本在 skill_active。通过 gateway_skill 查询当前源码和版本，修改工作区 Markdown，然后 test / publish。发布器先进行行为验收，包括实际使用观测工具、允许用户策略变化与维护工具的方法。失败不替换当前技能；成功后下一 Agent 步骤获取新版本，不需要重启聊天服务。

技能不保存部署地址、业务偏好、当前开发状态或一次故障经过。底座安全由权限和程序执行，不依赖 skill 自称不可更改。

## 证据和源码

源代码参考在可维护工作区 reference；受保护实际代码在系统上下文 code。两者要区分：编辑参考副本不会自动改变正式程序。维护者可主动为工具模块、巡检分析和方法提交经测试版本；受保护底座的边界由实际发布接口决定，不通过绕权限改文件。

## 调度策略与独立复核

gateway_audit_plan 可查询或调整审计间隔、常规任务日预算、选择依据。实际间隔同时满足预算；新故障与用户聊天立即处理。新版本和信心不足时默认约4小时，连续稳定后可以延长到12或24小时；你也可以依据测试覆盖、误报漏报与原始采样自主选择。计划有版本范围和有效期，不能用“程序说正常”取消独立复核。频率在运行数据中，不写死进skill。

普通采样不调用模型。已知故障先由程序处理并复测；无法处理的新故障立即升级。已经完成、证据没有变化的故障分析不会按时钟重复购买。独立审计检查原始观测、真实路径和程序覆盖本身；新的业务目标探测不正常时，不能用其他健康检查掩盖它。

巡检程序可附加 review_request={"fingerprint":"稳定的问题标识","reason":"实际证据与为何需要工程分析"}，其余返回字段不变。不要每轮生成新标识。外层会去重、限制常规预算并等谷价。

## 存储预算

实时上下文storage给出空间、inode、预算和是否暂停常规任务。独立程序清理重复后台报告、受控实验临时文件，按容量轮换注册的后台会话。普通用户聊天不自动删除，正在持有原生会话锁的记录不删；后台会话被用户接续后登记为用户聊天。配置、凭据、发布源码和必要回退点不属于日志清理范围。

实验临时文件放工作区.maintenance-tmp，遵守单文件和进程输出限额，不用大量小文件绕预算。空间低时推迟常规任务；紧急处理继续，先清理可再生成的实验产物与重复日志，不能把用户文件当缓存。

## 程序与偏好同步

实时系统上下文的 source_control 是同步状态来源，包含 repository_url、branch、result、last_attempt_at、last_success_at、local_commit、remote_commit、error_code 和 error_stage。remote_commit 只表示最近一次成功推送的提交，不表示此后刚发布的内容已经同步。状态不可用或 result=failed 时保持未确认，不能拿本地发布成功代替远端推送成功。同步由受保护程序完成，不读取推送私钥或模型凭据来手工试错。

正式发布或已验收偏好更新会返回 source_control_sync 并自动触发同步，无需维护者手动推送。source_control.pending=true 表示持久发布请求尚未被成功推送确认；acknowledged_request 是成功同步所对应的请求。发布期间的新请求继续排队；失败保留请求并由独立定时器重试，不把 GitHub 的故障变成本地发布失败。

## 原生自动化运行状态

上下文 native_automation 提供任务定义、最近程序准入和最近实际执行的有界摘要；需要详细内容时按需查询。原生独立执行历史区分 pending、started、completed、skipped、failed、interrupted、expired，并显示实际执行会话。只有 headless CLI 确认持久化 turn/end=completed、成功退出且未过期才计入成功审计；服务 active 和定时触发都不代表成功。

同一个原生任务保留身份和编辑记录，每次实际 AI 执行使用新的有界会话。程序检查跳过不进入来源会话，不产生模型调用。任务删除优先于后台自动恢复；gateway_audit_plan(restore) 必须有当前用户明确请求。gateway_audit_plan(set) 修改实际任务时间，不维护覆盖用户编辑的影子时钟。

原生常规复核遵守谷价窗口、至少两小时间隔、每日预算和磁盘预留。相同改进证据去重；新程序版本不继承旧版本成功审计的信心。根进程记录持久化执行身份以避免重启重放重复计费，任务回执有日数和条数上限，独立后台会话按存储预算处理。公开备份只保存任务定义与启用偏好，恢复后按偏好创建任务；已删除任务保持停用。

## 实际使用与路径对照

gateway(traffic_status) 是最近72小时的私有客户端观测，包含设备IP、域名、规则/链和保守的字节增量。2秒快照和告警流会遗漏短连接及不可观测的设备/应用，不是完整浏览历史；观测间断会标记过期。设备IP不等于人员身份。Pi控制和探测流量排除在外，不得把手选的探测域名称为家人在用的域名。

gateway(probe_compare,target=域名,endpoint=JSON) 在独立受保护引擎中固定 DIRECT 与实际选中节点，按实际观察的network/port/application_protocol验证TCP、TLS或HTTP阶段；未给端点时才使用兼容HTTPS根路径。UDP/QUIC等未支持端点明确返回未知，不偷换成443。三次采样分别返回相关阶段、业务未知/拒绝、路径身份和验收范围。通用首页200没有内容依据时仍未完成业务验收，403/429也不能笼统认定节点坏了。真实客户端错误不会被一次自测成功清除。

比较返回comparison_id与持久evidence_id。缓存命中复用同一轮和当时的正常对照，不构成新证据；refresh请求新轮也受最小间隔保护。实际网关规则另用自己创建的socket在实时连接中归属，不能凭出口IP或其他用户连接推断。控制探测与用户业务的适用范围始终分开。

巡检程序会基于真实域名定向复测，默认最多每10分钟一个目标、同域名至少30分钟。最近30分钟内三个跨至少一分钟的客户端拨号错误才形成反复故障证据；旧错误不会永久触发。后台常规检查不调用模型，新故障去重后立即交给AI，独立审计遵循当前预算。长期缺口仍需工程改进，不能以固定站点探测冒充覆盖。

维护工具的 self_test 必须声明 acceptance_cases，每条包含 request 和 expect。每个导出能力都要运行实际操作并满足预期字段，不能只自测分类器、再运行旧的无线观测，就声称新增路径能力通过。运行出错保留旧版；网络不可用等外部结果应返回结构化失败，不伪装成代码崩溃。

发布携带发起会话和内容版本；source_control.recent_publications 提供逐次 pending/held/failed/success/superseded 回执。只有实际推送快照证明包含该版本才算保存。原会话会自动收到不调用模型的原生通知，忙碌时延后、服务重启后续传。暂缓、失败和排队均不能称为已备份。编程shell通过去除监听权限的bwrap执行，凭据、聊天存储和特权socket不可见；正式操作仍用受保护工具。


节点池事件单独留存：快速切换可恢复的单节点失败不购买模型调用；首选池连续失败跨至少120秒或全部允许节点池确认不可用，会立即请求程序巡检。程序先重检节点，复测仍未恢复才走紧急AI；同一事件使用稳定指纹去重。显著但已恢复的事件保存有界摘要，供下次允许的复核审阅，不会被下轮正常采样抹去。

原生自动化的到期时钟使用 scheduled occurrence，模型实际启动时间只参与预算、最小间隔和期限。刚到期的任务不会被子秒调度差误跳过。最近一次因“未到期”跳过的任务，修正后可通过原生一次性补跑重用同一个执行ID和计划时间，保留原跳过信息；不修改用户任务内容或下次时间，也不生成重复模型执行。

后台任务通过 headless 原生标准输入传递 UTF-8 指令和观测，相同的 diagnosis/last_diagnosis 只发送一份，不受系统单个命令行参数长度限制。启动异常、执行超时、非零退出与缺失最终结果均保存明确失败摘要；已有工具或模型的部分输出不等于任务完成。先回写原生执行结果，再登记独立会话，避免网页登记延迟影响执行期限。后台报告保留有限失败类别、系统错误码和原生回执结果，不转储原始提供商 stderr。

## 事件处理与实际运维策略

gateway_incidents(list/get/decide) 维护跨新会话的事件。每项有稳定id、revision、事实、历史、priority、status、reason、evidence、next_review_at。decide使用刚读到的revision，证据变动会拒绝旧决定。status为open/working/verifying/blocked/closed，priority为urgent/normal，两者独立。

decide的decision JSON必须有reason、1至8个证据引用、未来Unix秒next_review_at。closed另需outcome=fixed/not_a_problem/no_route_remedy/external_dependency；fixed必须已有current_failure=false及verified_recovery=true的真实观测，不允许关闭复发检测。其他结论不代表业务恢复。关闭未修复事件必须明确给出当前 priority；not_a_problem 必须明确 normal。所有尚未证实恢复的 urgent 事件（包括暂无法修复或等待外部恢复）复查不超过15分钟；未到有效租约不重复唤醒，到期、修复失败或重要新证据继续接管。正常路径健康统计不受旧业务事件污染。容量和文件损坏是明确维护故障，待处理证据不会静默丢弃。

gateway_workflow(status/test/publish) 维护实际巡检的纯函数inspect(snapshot)，不同于只给建议的gateway_program。snapshot含schema_version=1、now、path_health={hard_faults,checks}、incidents（含requires_attention）、observations、routing（含当前preferences/routing_strategy）、audit。返回且仅返回summary、wake=none/routine/urgent、incident_ids、probe_domains、route_candidates、next_check_seconds。最多16个事件、各3个域名，检查建议30至900秒；实际采样受宿主定时器节奏限制。新的紧急关注及硬故障不能被策略抹去。坏代码回退前版，输入契约异常保留好版本并报维护故障。

候选位置从实时上下文sources.workflow_source读取；源码、有限测试、有效版本和前版由发布器持久保存。独立builtin不会被AI活跃源码覆盖；它不是用户可变目标的存放处。

## 公开依据与精确分流

gateway_routing(status/get/collect/requirement/evaluate/apply) 是独立受保护接口。status可按target域名查已有轻量引用，get按ID读取细节。先自主用原生web_search/web_fetch选取公开业务或地区资料，collect用无认证/参数的公开HTTPS URL取得真实来源收据；不接收模型自称已验证的正文。

requirement传精确target、所需path、source_ids、quotes=[{source_id,quote}]、rationale、region_context。程序核验真实来源、逐字引用、范围和时效；业务解释仍是维护者的责任，不等于程序证明语义真伪。来源/比较/业务依据是私有有界证据，不同步公开仓库。

evaluate使用独立比较evidence_ids和business_requirement_evidence_ids，按当时有效routing_strategy判断。当前实现要求同端点、政策/节点/DNS/配置身份以及真实客户端故障证据；正常对照由root采集，不接模型布尔。返回no_change/investigate/no_route_remedy/apply，前三者不会改变网络。apply只接受evaluate的proposal，锁内重读/CAS和重新评估，派生精确规则，持久装置回退，再热加载、实际规则/端点验证和正常对照；只有验证通过才提交配置与策略这一对检查点。不会给代理组添加静默直连兜底；传输阶段验证仍不冒充真实应用验收。

## 证据体积、事实与发布说明

起始与每步系统上下文只给语义摘要，同时保留失败、正常对照、处理进度及覆盖缺口。gateway_evidence按section/target/limit展开原始数据，snapshot_ref比较版本；requested_snapshot_matches=false时必须重新核对，不能无提示混用。模型任务报告记录原生tokenUsage已持久化总数、工具/处置/发布尝试，未取得用量时标为未知，不推算免费或声称已经修好。NRestarts只表示服务管理器的自动重启计数；生命周期记录、覆盖时段、无线PHY速率和吞吐分别表述，无法证明历史完整时明确未知。

publish/apply/set在现有模型轮次中提供commit_message。格式为中文Conventional Commit标题、空行、技术背景段落、按模块分组的行为/文档/测试，最后“验证：”实际结果。发布前在会话展示；不放凭据或私人日志。格式或敏感内容不合格会在改正式文件前拒绝。同步按实际导出版本/暂存文件匹配说明；已替代版本的文字不能套到新文件，也不会额外花一次AI调用写提交。

可公开维护测试以首8行内“# gateway-public-test: 1”标记，从Path(__file__).resolve().parents[2]定位src/maintained和src/operator，只使用公开源码与合成样本。不能依赖私人candidate路径、凭据或生产网络。有限导出会在无主机数据/网络、受限CPU/内存/输出的沙箱执行实际导出字节，失败不提交。旧的不可移植测试给出明确排除收据，不冒充通过；可用回归已转为当前公开源码的实际验收测试。

上下文中的 automatic_restart_count 只统计 systemd 自动重启计数，不能据此推断没有人工重启、看门狗恢复或进程退出；相关事实读取 runtime_facts 的生命周期记录。摘要最多缓存60秒，事件、策略、发布或恢复状态变动会立即失效；时间、内存等普通波动不应让每个推理步骤追加重复大段上下文。

当前 maintenance.cases 读取实时事件决定；workflow_evaluation_current=false 表示事件修订或复查期限已变，上一轮策略结论仅放在 last_workflow_evaluation 并明确标记历史。不能把历史 wake 或事件修订作为当前故障。下一次后台巡检负责重新执行工作流。

纯诊断程序的输入使用有限JSON与512KiB字节上限；宿主观测过大或格式错误会明确报告 input_unavailable 并保留有效程序，继续通过维护故障复核。不能把输入失败当成代码失败而删除有效发布。
