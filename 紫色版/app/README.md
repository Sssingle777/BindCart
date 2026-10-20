# 凭证防冒用 · Agent 支付演示

本交付包的默认入口是 **MyStore 商城 + 实时机制与手动支付控制台**。从 `ShoppingAuth` 根目录双击 [Start-Mac.command](../Start-Mac.command) 或 [Start-Windows.cmd](../Start-Windows.cmd)，由便携启动器打开带本次权限的双页演示。完整包自带 Node 和运行依赖，这条入口使用 Node 软件 eSIM，不需要 Java。操作步骤见 [随包启动与演示说明](../READ-FIRST.txt)；命令行和开发入口见 [运行](#运行)。

## 随包资料与源码

- [Verification.txt](../Verification.txt) 和 [release-verification.json](../release-verification.json)：随包验收记录。`sourceHashRefresh` 仅表示源码哈希刷新，历史浏览器结果不代表当前修改后重新验收。
- [FILE-SHA256.json](../FILE-SHA256.json)：列出包内文件的大小与 SHA-256；哈希一致只确认文件内容一致，不代表功能测试通过。
- [运行时来源](../runtime/provenance.json) 与 [第三方声明](../THIRD-PARTY-NOTICES.txt)：内置 Node 和第三方材料的来源。
- 实现入口：[便携启动器](../portable.mjs)、[双页服务启动器](launch-dual.mjs)、[商城 HTTP 服务](lib/storefront/live-server-process.mjs)、[支付控制器](lib/storefront/controller.mjs)。

本包未附原开发项目的 `docs/` 文档和截图。下文保留的原路径均标为“未随包提供”，用于辨认历史材料；它们不是可打开的本地文件，也不作为当前验收证据。技术细节可直接核对本包源码和测试。

## 开发平台背景

`npm start` 启动的 **开发平台** 提供 **演示平台 / 凭证与设备 / 安全实验 / 付款授权** 四个模块，辅助工具统一收纳 **基础 JWS 对照 / 机制诊断**。默认进入 **01 正常支付 / 02 复制凭证冒用 / 03 撤销后使用**，先选择要验证的问题，再按当前主按钮推进，查看实际返回的验证结果与可展开证据。主平台、管理、实验、审批及辅助页面使用同一套导航和视觉规范。下面的四模块和三场景说明适用于该开发入口；便携商城的手动步骤见上面的随包演示说明。

**场景化交互演示台（2026-10-12）：** 主入口首次默认紧凑演示视图，顶栏唯一三个场景导航，保留“平台工具”和“展开平台导航”。主画面为真实业务摘要、阶段进度、左侧角色交互画布、右侧单一当前步骤面板；证据与历史记录通过节点、消息或本步证据入口进入统一只读抽屉。普通/盲化模式始终可见，操作节奏与模式切换在“演示设置”。显示偏好只影响布局，不刷新 iframe，不触发签发、认证或付款。新订单和结束尝试收在“更多操作”，原禁止条件与确认继续生效。实现映射、实际测试与截图见本次改版验收（原路径 `docs/scenario-stage-acceptance/README.md`，未随包提供）。

**其他工作区视觉统一（2026-10-12）：** 紧凑／展开导航现在是全平台显示偏好，沿用 `a2a-demo-display`；临时“平台工具”浮层与展开侧栏分开。管理、实验、授权、JWS 对照与机制诊断沿用主演示页的顶栏和宽画布，主页面结构、三个场景及业务控制器保留。公共组件限定 `.platform-workspace`，不会给 guide 加载其他工作区规则。共享样式以 `public/tokens.css` 和 `public/platform.css` 为维护源；编辑后运行 `npm run styles:sync` 更新独立 Owner 入口的本地副本，`npm run styles:check` 或完整测试会检查一致性。验收、实际截图及边界见视觉统一验收（原路径 `docs/platform-style-acceptance/acceptance-report.txt`，未随包提供）。

**平台调整（2026-10-12）：** 已移除独立“支付调试详情”模块及其专用控制器、样式，付款流程统一在主演示页按步骤进行。原入口及书签返回演示平台，主页面的公开材料、逐项验证、业务记录与回执继续保留。当前开发服务的页面路由见 [agent-a.mjs](agent-a.mjs) 和 [导航模型](public/navigation-model.js)，本次移除验收见验收记录（原路径 `docs/remove-payment-detail-acceptance/acceptance-report.txt`，未随包提供）。原平台整理验收（原路径 `docs/PLATFORM-CONSOLIDATION-VERIFICATION.md`，未随包提供）和 README 下方旧测试数、截图保留为对应历史版本记录。

三个场景保留独立页面 `/guide/normal.html`、`/guide/copied-vc.html`、`/guide/revoked.html`；统一入口使用 `#view=guide&scenario=...` 表示当前场景。刷新、前进/后退、模块切换与模式切换读取现有状态，不会因此新建认证、重跑实验或付款。运行中的操作会锁定跨模块切换，避免在请求未结束时修改上下文。仍需从本次启动的统一演示链接载入权限。

核心威胁是**攻击者复制合法公开 VC，但没有持有者私钥及原绑定设备的秘密或调用权限**。演示页使用一个随当前动作切换的主面板，依次显示步骤任务、必要摘要、操作或核验记录、结果与操作。材料在对应事项内按需展开；资格认证、付款前复核、结算验证按实际阶段和检查 ID 分别显示本次结果，前置记录仅作为只读回看。认证通过、Owner 批准、钱包签名和支付完成分别呈现；不能拿历史结果宣布新请求通过。

版本 **0.5.0**。底层主线是 **W3C VC 的标准 bbs-2023 签发与选择性披露 → 论文 BBS-BLS / BBS-BlindBLS 的软件 eSIM 设备绑定 + 持有者 Ed25519 请求签名 → Owner 单笔确认 → x402 本地测试链付款**。同一受信 Issuer 共同签发标准 VC 和配套设备绑定材料；两者通过签名覆盖的随机 bindingId 关联，每次支付展示再绑定同一挑战与精确派生 VC 哈希。标准层、持有者签名、设备层、可信本地凭证状态及请求绑定必须通过，不能拼接两次不同签发或不同请求的材料。原具名 VC + JWS / jCardSim 流程保留为基础对照。由原 `a2a-did-vc` 复制后独立改造，原目录保持不变。

密钥、权限与软件仿真边界见 [密钥与授权检查](#密钥与授权检查)；请求绑定和逐项验证见 [支付验证器](lib/dbac/payment-verifier.mjs)，实验前提和拒绝判据见 [攻击实验实现](lib/dbac/attack-experiments.mjs) 与 [攻击回归测试](test/framework-attacks.test.mjs)。这些链接指向实现和测试定义，实际执行结果以当次运行为准。场景导览复用已有 BBS、设备贡献、A 侧 Ed25519 签名和撤销验证，没有替换密码学检查；联合持有证明不称为门限签名。Owner、认证及支付执行仍是独立状态。

当前主线的“模拟 eSIM”是 **独立 Node BLS12-381 软件签名设备**，基础 JWS 对照使用 **jCardSim Java Card 软件设备**；两者都不是运营商 eUICC。**TEST_USDC 没有真实资金价值，也不是 Circle 发行的 USDC。**

2026-10-03 增加论文 **BBS-BLS / BBS-BlindBLS 设备绑定匿名凭证**入口：实现 BBS 签发、公钥随机化、签名适配和选择性披露知识证明。该实现使用独立 Node BLS12-381 软件设备，最初运行 `demo:echo`，现另以 `payments:pay` 凭证接入实际测试代币支付；两种权限不能互换。原具名对照流程仍使用 jCardSim P-256。论文 Fig. 5 / Sections 6.3、6.4 的实现与自定义编码边界见 [DBAC 密码学模块](lib/dbac/crypto.mjs)，标准 bbs-2023 层见 [W3C 凭证模块](lib/dbac/w3c-profile.mjs)。2026-10-03 的机制验收记录原路径为 `docs/DBAC-VERIFICATION.md`（未随包提供）。

## 运行

### 便携商城入口

完整解压后进入 `ShoppingAuth` 根目录（本 README 所在 `app/` 的上一层），使用对应平台的入口：

| 平台 | 启动 | 停止 |
| --- | --- | --- |
| macOS Apple Silicon / Intel，macOS 13.5+ | [Start-Mac.command](../Start-Mac.command) | [Stop-Mac.command](../Stop-Mac.command) |
| Windows x64 | [Start-Windows.cmd](../Start-Windows.cmd) | [Stop-Windows.cmd](../Stop-Windows.cmd) |

启动器自动选择端口，打开 `/demo/`，其中包含左侧商城和右侧控制台。重复运行 Start 会重新打开本副本的演示。关闭浏览器或关闭启动脚本所在的终端窗口，不会停止后台服务，请使用对应 Stop 入口。终端的 `Ready: http://127.0.0.1:<port>/demo/` 只显示无权限的基础地址；需要操作权限时重新运行 Start，由它打开本次授权网址。

这条启动链是 `Start → portable.mjs → app/launch-dual.mjs`，只使用 Node BLS 软件设备，不启动 jCardSim。完整包无需运行 `npm ci` 或 `npm run setup`。浏览器自动验收需要另行准备可供 Playwright 启动的浏览器，详见 [状态、测试与提交边界](#状态测试与提交边界)。

### 开发平台入口

开发命令需要 Node.js **22.13+** 和 npm。以下命令从 `ShoppingAuth` 根目录执行；若终端已在 `app/`，跳过第一行：

```sh
cd app
npm ci
npm run setup
npm run test:card
npm start
```

`npm start` 会启动基础 JWS 对照的 jCardSim 设备，因此需要 **JDK 11+，含 `java` 和 `javac`**。`npm run setup` 的自动 JDK 下载仅面向 macOS Apple Silicon，并需要网络；其他平台或已有 JDK 的机器，应先在当前终端设置 `JCARD_JAVA_HOME` 为实际 JDK 根目录，再运行上面的 setup 和自检。可接受的路径布局是 `<JCARD_JAVA_HOME>/bin/java` 与 `<JCARD_JAVA_HOME>/bin/javac`。未设置时，运行时只查找 `app/.runtime/jdk/Contents/Home` 或 `app/.runtime/jdk`，不会自动使用系统 `PATH` 或 `JAVA_HOME`。缺失局部 JDK 时会报 `JCARD_JAVA_REQUIRED`，不会改用 Node 代签。下载与查找规则见 [setup 脚本](scripts/setup-jcardsim.mjs) 和 [jCardSim 后端](lib/jcardsim.mjs)。

setup 不修改系统 Java 或全局环境变量。如果安装依赖时 npm 官方 `.org` 域名出现证书故障，可使用 `npm ci --registry=https://registry.npmjs.com --replace-registry-host=always`；不要关闭 TLS 校验。前台开发服务使用 Ctrl+C 退出。

本次移除的页面入口和导航可通过刷新浏览器更新；运行中的旧服务访问退役页面时只显示返回主演示页的跳转。下次正常启动会使用新的 HTTP 兼容跳转及资源表。服务重启会更换本次访问权限并丢失内存中的实验/认证会话；应先核对未确认的原订单，再使用新输出的统一演示链接。

`npm start` 启动后，打开终端输出的 **统一演示链接**（下列省略号只是格式示例）：

```text
http://127.0.0.1:4340/#key=...&ownerKey=...&view=guide
```

同一个网址始终保留四个主模块导航。默认“演示平台”显示三场景导览；普通/盲化模式与执行节奏位于导览设置中。正常支付在主演示页按当前主按钮推进；可选择逐条消息执行。当前步骤中查看原始/派生 VC、设备公开输入输出、持有者 A 签名与验证者 B 检查，技术详情保留只读业务记录，支付完成后查看本笔回执。

明确修改凭证或设备会作废不再适用的材料。刷新及普通/盲化模式切换只读取状态，各模式的订单、认证材料、Owner 授权和待结算付款材料独立保留。待结算订单禁止重置；过期挑战必须明确重新获取。默认逐步观察设备参与也不会自动批准、自动跨过钱包确认或自动提交最终结算；页面切换不会付款。访问能力载入后从地址栏移除，整组服务重启须使用新链接。

两个旧私有链接继续兼容：

- **控制台链接**：`http://127.0.0.1:4340/#key=...`
- **Owner 确认链接**：`http://127.0.0.1:4343/#key=...`

`#key` 是控制台权限，`ownerKey` 是独立的 Owner 批准权限。普通控制台链接不会自动取得 Owner 权限；可在“付款授权”粘贴本次 Owner 专用链接载入。Owner 仍运行于独立进程，浏览器通过同源 `/owner/api/` 代理提交自己的 Owner 凭据，代理不代填批准权限。**统一入口面向本机演示，会在同一浏览器来源承载两种权限，不提供浏览器角色隔离**。订单依然需要明确的逐笔确认。裸地址可以看页面，但不能进行管理操作。B 的 `http://127.0.0.1:4341/a2a` 是 JSON-RPC API；设备接口默认使用 4342。若端口占用，可用 `PORT=0 AGENT_B_PORT=0 ESIM_PORT=0 OWNER_PORT=0 npm start`，以新输出的地址为准。

### 临时验收实例

要隔离四模块开发平台的状态，在满足上述 Node / JDK 条件后，从 `app/` 使用以下 macOS / POSIX shell 命令。它为本次运行分配临时链、数据库和动态端口，不删除已有状态：

```sh
DEMO_CHECK_DIR="$(mktemp -d)" && \
X402_STATE_DIR="$DEMO_CHECK_DIR/x402" PAYMENT_DB="$DEMO_CHECK_DIR/payment.sqlite" \
  PORT=0 AGENT_B_PORT=0 ESIM_PORT=0 OWNER_PORT=0 npm start
```

使用该实例新输出的统一演示链接；前台 Ctrl+C 结束后，临时目录保留供核对。这些变量用于 `launch.mjs`，不是便携入口的状态参数。双页服务的隔离参数为 `DUAL_STATE_DIR`、`DUAL_RUNTIME_PATH`、`DUAL_PORT`，定义见 [launch-dual.mjs](launch-dual.mjs)；便携启动器按当前包目录管理自己的状态。不要用新实例的订单代替查询原支付结果。

## 按钮演示流程

推荐先在默认导览完成下面三种场景。A 使用当前正常业务会话；B/C 使用专用实验订单和凭证，并通过同一个生产验证入口 `/dbac/payment/a2a` 取得结果。

| 场景 | 点击与实际执行 | 应核对的结论 |
| --- | --- | --- |
| **A 正常支付** | 选择 A → 准备演示凭证 → 准备请求与披露材料 → 请求模拟 eSIM 贡献 → 由 A 核验并组合 → 提交 B 验证 → 提交授权申请并明确批准或拒绝 → 用新挑战和设备贡献复核付款资格 → 明确签署钱包材料 → 再次准备结算证明 → 明确提交 B 验证并执行模拟支付 | 资格通过、Owner 批准、钱包签名和支付完成分开显示；只有匹配当前订单条款的真实测试链回执才表示模拟支付完成 |
| **B 复制凭证冒用** | 选择 B → 运行本场景；后端先签发实验凭证并验证合法控制组，再让攻击分支仅复制公开 VC、获取新挑战、派生标准 BBS 证明并提交 B | 攻击分支没有 A 私钥或原设备调用权限。标准 BBS 派生本身可以完成，B 实际拒绝原因与后续未执行检查以返回 trace 为准；不能宣称“复制 VC 无法派生” |
| **C 撤销后使用** | 选择 C → 运行本场景；合法控制组先通过，再撤销实验专用凭证，用新挑战、原持有者和原设备重新生成完整证明并提交 | 核对 B 是否在凭证状态查询处拒绝。必须区别于旧挑战重放、设备锁定或缺少签名；撤销的是本次实验凭证，不是用户当前正常演示凭证 |

B/C 一次请求执行完整的原实验，期间显示等待，返回后呈现真实记录与检查顺序；没有逐步操作的实验 API，也不以计时动画假装某一步已经通过。准备合法控制组会调用软件设备，只有 B 的攻击分支不具备合法设备能力。B/C 不请求 Owner 批准、不调用钱包签名、不执行结算，并返回余额及付款执行次数的前后观察。实验使用独立订单和凭证，但与正常会话共享签发方、软件设备服务和测试账本，因此设备调用次数/日志会增加。

正常支付默认“逐步观察设备参与”：仅将取得挑战与派生 VC 合并为一次准备操作；请求模拟 eSIM、A 核验并组合证明、提交 B 验证、提交 Owner 申请分别停留，由用户点击继续。切换“逐条消息执行”后，挑战和派生也分别点击。三个认证阶段都使用各自的新挑战与新设备贡献，不复用前一阶段的通过记录。挑战保持真实 60 秒有效期；讲解可在取得结果后展开记录，不为演示自动延长时效。

当前主面板内显示本轮设备参与链：A 准备输入 → 模拟 eSIM 返回贡献给 A → A 核验、组合并独立签名 → B 验证绑定与本次贡献。前面三项使用材料/操作状态，B 两项分别读取 `vc_device_binding` 与 `device_pairing` 的真实子项结论。普通模式的设备请求包含上下文；盲化模式设备输入仅包含公开协议字段和 `blindedPoint`，明文上下文只标为 A 本地材料。签发阶段展示已返回的绑定材料，不虚构注册子步骤的独立验证记录。

B/C 在当前主面板内并列两条简短实际结论：复制场景对照标准 BBS 与设备绑定，撤销场景对照设备贡献与凭证状态。仅本轮返回的真实子项支持结论；无结果、未执行或通信异常不会显示拦截成功。复制场景仍以攻击者没有 A 私钥及原设备调用权限为前提。

以下能力继续保留，入口与平台导航一致：

| 入口 | 操作与验证依据 |
| --- | --- |
| 演示平台 | A 正常支付的完整阶段流程；B 复制冒用与 C 撤销实验；当前步骤、公开材料、逐项检查及真实回执 |
| 凭证与设备 | 选择证明模式、凭证和设备；准备凭证、撤销凭证、创建/锁定/解锁设备；查看指纹、状态和脱敏调用记录 |
| 安全实验 | 选择完整攻击目录中的场景，运行单个实验；分别核对请求拒绝、是否符合预期、真实验证轨迹和副作用；过期场景真实等待约 61 秒 |
| 付款授权 | 独立核对金额、资产、网络、收付款地址和订单，明确批准或拒绝；批准后回原流程同步授权 |
| 基础 JWS 对照 | 完整具名 VC、持有者与 jCardSim 的两份独立签名、具名付款及安全用例；JWS 是签名封装格式，不等于不安全 |
| 机制诊断 | 论文设备绑定协议的独立 echo 检查、两次展示随机化对照和锁定实验；折叠保留支付批量诊断及同单幂等重试 |

“新订单”使用新标识及新的审批，不能代替核对未知的原支付结果。当前没有一键清空环境按钮；要初始化独立测试环境，请使用 [临时验收实例启动方法](#临时验收实例)，不删除原有状态目录。需要演示“撤销后仍由合法双方生成新证明”，优先使用 C 场景或安全实验中的撤销用例；不要把旧工作台已经移除的按钮作为当前操作说明。

B 的检查按凭证来源与状态、持有者与设备证明、请求绑定与新鲜性呈现，保留通过、未通过和未执行。公式说明不是运行证据，显示公开签名载荷不是验签；缺失检查、环境故障和超时不能显示认证成功或攻击拦截成功。原始报文与完整验证记录可展开查看。独立持有者单方基线尚未实现，不展示虚构成绩；同单幂等返回旧回执与认证重放拒绝是不同概念。

开发平台的页面入口和旧 hash 兼容规则见 [导航模型](public/navigation-model.js) 与 [导航测试](test/platform-navigation.test.mjs)。旧三步首页、八组检查和原导航截图见历史三步凭证流程验收（原路径 `docs/CREDENTIAL-FLOW-VERIFICATION.md`，未随包提供）、历史逐消息指南（原路径 `docs/MANUAL-ESIM-DEMO.md`，未随包提供）与历史四模块指南（原路径 `docs/FRAMEWORK-GUIDE.md`，未随包提供）；这些文档中的旧工作台入口和布局已经被本次平台整理替代。

## B/C 实验查询与恢复

新导览先在当前浏览器会话中保存 UUID 运行编号，再调用 `POST /api/dbac/payment/experiment-runs`，提交 `runId / mode / scenarioId`。后端立即返回运行记录，随后执行原实验；前端通过 `GET /api/dbac/payment/experiment-runs?runId=...` 核对同一运行。相同编号和参数重复提交只返回原记录，改变参数会被拒绝。实验运行期间，其他变更操作返回 `BUSY`，状态和结果查询仍可用。旧同步 `/api/dbac/payment/experiments` 接口保持兼容。

- 页面刷新、开始请求超时或响应丢失时，使用“核对原运行”；前端不会因此自动新建实验。自动查询达到上限后会停止轮询，需再次明确核对原运行。
- `running` 表示执行尚未返回；`completed` 表示原实验函数已有返回，仍需读取其中的实际请求结论、完成情况、验证记录和副作用；`failed` 表示运行异常。三者均不能仅凭状态名宣布“冒用已阻止”。
- 运行记录只保留在 **Agent A 进程内存**，最多 64 条，列表返回最近 10 条；已接收编号不自动淘汰，以免旧重试再次执行。达到上限明确返回容量错误。
- 服务重启后查询旧编号返回 `EXPERIMENT_RUN_NOT_FOUND`。页面保留“原记录不可恢复”的说明，不把它解释为取消、撤销或安全拒绝，也不自动重跑；再次演示须明确点击“新一轮”。当前浏览器会话存储不可用时，新导览不会先启动一个无法保存编号的实验。
- 实验记录不是认证授权凭据，也不是持久审计归档。测试链回执、钱包状态和撤销表的持久化规则见下文，它们不意味着实验运行、Owner 会话或原证明材料能在重启后恢复。

## 辅助机制检查

开发平台的完整论文支付使用上面的 `npm start`。仅需检查凭证数学机制、且不需要 Owner 或测试链时，可在已安装依赖的 `app/` 目录运行（无需 JDK）：

```sh
npm run start:dbac
```

打开终端输出的统一演示链接，默认控制台端口 4350、B 端口 4351；端口冲突可用 `DBAC_PORT=0 DBAC_AGENT_B_PORT=0 npm run start:dbac`。此模式仅开放“机制诊断”，默认展开“独立机制检查”，支付按钮及未启动的角色入口不可用；原 `/dbac.html#key=...` 链接仍兼容。此入口启动 A、B、Issuer、BLS 软件设备四个独立进程，不启动 jCardSim 或支付链，不读取默认 `var/`。完整的 `npm start` 提供上述四个一级模块。

在“独立机制检查”中依次点击“准备 BBS 凭证”→“生成证明并提交验证”→“连续生成两次展示”→“运行攻击验收”。切换 BBS-BlindBLS 后需为新模式另签凭证；两模式采用不同设备密钥。可对照本地凭证与 B 实际收到的 JSON，并锁定设备验证新展示被阻止。四角色启动关系见 [DBAC 运行时](lib/dbac/runtime.mjs)，公式映射见 [密码学实现](lib/dbac/crypto.mjs)。

辅助 `/dbac/a2a` 路径处理 `demo:echo`；主线 `/dbac/payment/a2a` 处理 `payments:pay`，两者有独立挑战和用途约束。辅助论文证明及主线中的配套设备证明仍是自定义 DBAC 编码；完整支付主线已另行接入真实 W3C `bbs-2023` 标准层。两者不能混称同一个标准 proof，软件设备也不具备真实 eSIM 的硬件保证。

## 实际使用的组件

| 层 | 本版实现 |
| --- | --- |
| 通信 | A2A 0.3.0 JSON-RPC、AgentCard、签名请求/回执 |
| 主线 W3C 凭证 | VC 2.0、DataIntegrityProof / bbs-2023；Digital Bazaar 标准库；固定离线 context 与受信 Multikey |
| 持有者、基础对照与支付授权 | 主线每张凭证独立 A Ed25519 密钥及受签名 holderDid；具名 DID/VC + JWS；Owner Ed25519；对照设备 P-256 did:key / ES256 |
| 模拟卡 | jCardSim `com.klinec:jcardsim:3.0.6.0` 社区发行版、定制 Java Card applet、真实 APDU 调用 |
| 支付协议与 SDK | x402 v2；`@x402/core@2.28.0`、`@x402/evm@2.28.0`；A2A 支付扩展 |
| 本地支付执行 | Ganache 7.9.2，`eip155:31337`；自建 TEST_USDC / EIP-3009；viem 2.57.2，solc 0.8.30 |
| 持久状态 | 本地链、测试钱包、订单签名 nonce、链上回执、VC 撤销记录 |
| 论文设备绑定及支付 | BBS-BLS / BBS-BlindBLS；`@noble/curves@1.9.1` 的 BLS12-381；独立软件设备与 Issuer；VC 共同绑定、三阶段新证明、单订单公钥、Owner 精确条款授权及 x402 结算 |

jCardSim 二进制来源是 [ph4r05/jcardsim](https://github.com/ph4r05/jcardsim) 发布到 Maven Central 的社区分支，不宣称为 Licel 最新官方二进制。来源、SHA-256、许可证、APDU 表及**必需的模拟器随机数修补**见 [javacard/README.md](javacard/README.md)。实际测试发现该分支默认随机源在新 JVM 间生成相同密钥，因此本版用 JVM `SecureRandom` 替换，并在未加载修补时拒绝启动。

协议字段见 [A2A 实现](lib/protocol.mjs)，付款阶段与状态见 [DBAC 支付会话](lib/dbac/payment-session.mjs)。原具名支付版本在 2026-10-02 的 **260/260** 回归记录保留于具名支付验收记录（原路径 `docs/VERIFICATION.md`，未随包提供）。2026-10-03 加入辅助论文机制时的历史全项目回归为 **299/299**，论文测试 **39/39**，两模式四进程演示各 **11/11**；真实浏览器的两模式按钮流程通过，默认 `npm start` 集成验收 **7/7**。各层验收的范围和原始证据见论文机制验收记录（原路径 `docs/DBAC-VERIFICATION.md`，未随包提供）。

## 密钥与授权检查

- **设备密钥**：在 jCardSim applet 生成 P-256 私钥，只提供公钥和 APDU 签名。Node 不接收私钥；JVM 异常时拒绝签名，没有 Node 备用签名。卡内锁定阻止新设备证明；调用权限、订单绑定等策略仍在 Node 服务检查。
- **主线设备密钥**：由独立 Node BLS12-381 软件设备按模式生成，不在 jCardSim 中。标准 BBS VC 与配套 DBAC 证明共同构成支付资格检查；每个阶段要求新的设备贡献，凭证有效性采用公共 UTC 日期。
- **支付钱包密钥**：是本地测试钱包的 secp256k1 软件密钥，用于 EIP-3009；没有放入 jCardSim。具名分支验证 VC、设备响应和当前撤销状态；DBAC 分支独立验证可信 Owner 授权、B 签署的当前支付阶段证据和订单公钥，并查询可信本地 Issuer 的 bindingId 状态；未知或查询失败拒绝释放新签名。钱包与结算服务使用不同访问权限。

Owner 的签名绑定订单、整数金额、币种、网络、代币合约和收付款地址；W3C 主线还绑定凭证配置、可信 W3C Issuer 和 `bindingId`。具名分支在撤销查询失败时停止签发载荷，结算前再次校验身份、授权与当前 VC 撤销状态。主线在凭证撤销/状态未知、Owner 授权、当前日期或阶段证据失效时停止签名和新的结算；已存在订单不能切换具名/DBAC 类型、订单公钥或 VC 绑定。每个订单固定链上授权 nonce；重试、并发和重启通过持久记录及链上事件恢复同一回执，避免重复转账。结算超时可能已广播，不能把“超时”等同于“未付款”，应查询或重试同一订单。

**已经发出的有效 EIP-3009 签名无法通过本项目 VC 撤销或设备锁定在链上追溯取消。** 持有完整载荷者可直接提交到链；短有效期和一次性 nonce 限制其使用。设备锁定也不能收回已签发的设备证明。

## 状态、测试与提交边界

便携商城在包根目录下的 `app/var/dual-live/` 保存链、订单、商家身份与事件；启动元数据为 `app/var/dual-runtime.json`，日志为 `app/var/dual-start.log` 和 `app/var/dual-error.log`。请使用相应 Stop 入口关闭；核对未知结果时保留原状态，不要把运行后的状态、钱包或带权限的网址随包转发。

开发平台 `npm start` 的默认持久数据在 `app/var/`（下列相对路径以 `app/` 为基准）；可通过 `X402_STATE_DIR` 和 `PAYMENT_DB` 指定独立位置。`var/x402` 含测试钱包私钥，目录/文件权限收紧到 0700/0600，**不要将它、运行日志或带 #key 的链接作为比赛公开材料**。Ganache RPC 仅监听本机，是具有管理能力的开发链；本机不可信进程仍可能操作它。正常退出用 Ctrl+C。重启重新生成 Agent/Owner/卡身份和访问口令，测试链余额和已结算回执保留；旧身份绑定的未执行授权不能直接继续使用。底层重启恢复测试保留同一组可信身份；默认启动器尚不恢复旧 A2A Task 或 Owner 会话。若整组服务在链上转账后、本地回执落盘前退出，需要按原交易/nonce 核对链上记录，不能用新订单自动补付。

以下开发测试从 `app/` 执行，使用系统 Node.js 22.13+ 和已安装的依赖。`npm test` 包含 jCardSim 用例，需要上述局部 JDK；支付和服务测试还需要本机回环端口可监听。`playwright-core` 依赖本身不附带浏览器。缺 JDK、浏览器或外部 fixture 时，应分别记录环境阻塞。

MyStore、native、手动控制台、后端布局及窄屏诊断中原先固定 Edge 的 9 个脚本现使用[共享浏览器启动器](scripts/lib/acceptance-browser.mjs)，默认依次尝试已安装的 Microsoft Edge、Google Chrome、与当前 Playwright 版本匹配的 Chromium。只有浏览器可执行文件不存在时才尝试下一项；权限、依赖、崩溃和超时错误直接报告。脚本不会自动下载浏览器，成功启动后会打印实际选择及版本。

这 9 个脚本可通过 `PLAYWRIGHT_BROWSER_CHANNEL`（如 `chrome`、`msedge`、`chromium`）或 `PLAYWRIGHT_BROWSER_EXECUTABLE_PATH`（实际浏览器可执行文件路径）指定浏览器，两者不能同时设置。显式指定后不再回退到其他浏览器。其他旧验收脚本保留各自的启动选项，不能据此假定都支持这两个变量。

以下命令运行独立 HTTP fixture，验证模拟订单的页面交互，不连接当前演示实例，不执行真实密码学或链上付款；输出放入新建临时目录，避免覆盖已有截图：

```sh
FIXTURE_CHECK_DIR="$(mktemp -d)" &&
  FULL_MYSTORE_FIXTURE_OUTPUT_PATH="$FIXTURE_CHECK_DIR" \
  PLAYWRIGHT_BROWSER_CHANNEL=chrome \
  node scripts/full-mystore-fixture-check.mjs
```

未指定 `FULL_MYSTORE_FIXTURE_OUTPUT_PATH` 时，该脚本仍写入包根目录的 `evidence/full-mystore-fixture/`。浏览器能启动只说明启动条件满足，具体页面、外部 fixture 和业务断言仍须由当次运行验证。

[初始化竞态验收](scripts/native-mystore-initialization-check.mjs)也使用独立 HTTP fixture。它挂起首次状态读取，检查 SSE 提前显示已完成订单时，返回首页点击及一次合成重复点击事件必须等待初始化，随后只重置一次并清空购物车；另检查已有购物车不会因打开结算路由自动下单，待确认订单不会因提前导航或刷新被重置。三个场景均检查刷新恢复，并拒绝隐式支付、查询、Owner 批准和签名请求。

```sh
INITIALIZATION_CHECK_DIR="$(mktemp -d)" &&
  NATIVE_INITIALIZATION_OUTPUT_PATH="$INITIALIZATION_CHECK_DIR" \
  node scripts/native-mystore-initialization-check.mjs
```

未指定 `NATIVE_INITIALIZATION_OUTPUT_PATH` 时，报告写入包根目录的 `evidence/native-mystore/initialization-race-verification.json`。这些浏览器 fixture 使用模拟后端状态，不作为密码学、真实结算或现有演示实例的验收证据。

可先运行不依赖浏览器的定向检查：

```sh
npm run styles:check
node scripts/native-mystore-source-check.mjs
npm run test:dual
```

其他测试按所需环境执行：

```sh
npm test
npm run test:card
npm run test:x402
npm run test:dbac
npm run demo:dbac
node --test test/dbac-payment-wallet.test.mjs
node --test test/w3c-bbs.test.mjs test/w3c-binding.test.mjs
node --test test/experiment-runs.test.mjs test/guide-model.test.mjs test/guide-experiments.test.mjs
node --test test/guide-payment-flow.test.mjs
```

测试使用临时链与数据目录。少量旧 CNY SQLite 单元测试只做兼容回归；正式 `npm start` 的 B 要求 x402 后端，缺失时拒绝付款。macOS Node 22 下 Ganache 可能提示 µWS 本机二进制不兼容并回退到 JavaScript，这是已验收的运行路径。

本版尚不包含真实 eUICC/profile 下载、真实卡安装/CAP 与物理防提取验证、真实资金/人民币支付、主网部署、AP2 或两方门限签名；未获得官方互操作认证。标准 BBS 选择性披露与论文设备绑定已在同一主线验证，但配套设备证明不是 W3C 原生 eSIM 能力；同一 VC 的公开 bindingId、链上地址、金额和订单仍可关联。凭证采用公共 UTC 日期到期策略，并已支持基于受签发方保护 bindingId 的本地逐凭证撤销；状态表持久化，持有者与签发方等演示秘密仍在重启时重建，持久撤销记录不等于恢复旧凭证。该状态机制不是隐私保持的标准撤销基础设施；同一凭证的 bindingId 和 holderDid 可关联其多次展示。固定离线 context 与 `did:example` Issuer 是本机演示信任配置，不代表生产 DID 注册解析。软件模拟器与 Node 软件设备均不能提供硬件隔离保证。`docs/baseline-v0.4/`（未随包提供）仅归档旧版资料，不能作为新版验收证据。

## 历史界面验收记录

以下段落保留原 README 对各历史版本能力、测试数与截图的记载。段落中的“本版 / 本轮”仅指当时版本，**不代表当前代码重新执行，也不代表旧工作台仍提供服务**。所列 `docs/` 报告与截图未随包提供，无法在本包内复核这些历史数字；随包记录入口见 [随包资料与源码](#随包资料与源码)。本次文档修订没有重跑浏览器、支付或全量回归。

**历史：设计令牌改版（2026-10-11，早于本次平台整理）：** 新增设计令牌 `public/tokens.css`（`/tokens.css`、`/owner/tokens.css` 路由），七个页面统一为冷灰白 + 深墨蓝强调色的新视觉体系，替换并存的三套旧配色；guide 主舞台、外壳侧栏、管理/攻击、高级工作台、JWS 对照、诊断辅助与 Owner 页全部换装，组件圆角/按钮/徽章几何统一。文案术语同步统一：检查结果一律显示 **通过 / 未通过 / 未执行**，角色称谓统一 **持有者智能体 A / 验证者智能体 B**；不改任何业务逻辑与元素 ID。**本轮改版后 `npm test` 565/565 通过，0 失败，110.226 秒**；浏览器完成 A 正常支付（EXECUTED 回执）、B 复制冒用拒绝（`W3C_DEVICE_PROOF_REQUIRED`）、C 撤销拒绝（`W3C_CREDENTIAL_REVOKED`）及 13 页 1280/390 截图复核。详见改版验收记录（原路径 `docs/UI-REFRESH-VERIFICATION.md`，未随包提供）与截图目录（原路径 `docs/ui-refresh-screenshots/`，未随包提供）。**改版后需要重启后端并使用新统一演示链接。**

**历史：三页面与比对明细验收（2026-10-10）：`npm test` 565/565 通过，0 失败，107.896 秒。** 浏览器已验证普通模式资格认证与一笔 2.99 TEST_USDC 模拟支付、复制冒用拒绝、撤销拒绝、独立页面刷新和前进后退、原实验编号恢复、键盘及 1280px / 390px 布局。撤销比较记录来自实际可信状态查询：预期 `valid`、实际 `revoked`、`match:false`，验证决策保持不变。见本轮验收记录（原路径 `docs/SCENARIO-PAGES-VERIFICATION.json`，未随包提供）、完整回归输出（原路径 `docs/SCENARIO-PAGES-REGRESSION.txt`，未随包提供）和截图目录（原路径 `docs/scenario-pages-screenshots/`，未随包提供）。

**历史参考图改版验收（2026-10-10，不代表本轮侧栏与证据明细改版）：最终 `npm test` 549/549 通过，0 失败，108.963 秒；相关脚本语法检查通过。** 新增四段进度与统一回执判据测试，并把导览页面和新脚本纳入实际静态资源检查。本版浏览器完成普通模式两笔模拟支付、复制冒用、撤销及重复撤销、模式隔离、重置、键盘弹窗、桌面和390px检查，见参考图改版验收（原路径 `docs/REFERENCE-LAYOUT-VERIFICATION.md`，未随包提供）与本版最终回归输出（原路径 `docs/REFERENCE-LAYOUT-REGRESSION.txt`，未随包提供）。项目使用直接加载的 HTML/CSS/JS，没有独立 build 脚本。

前一版场景导览的 **531/531** 及两模式浏览器操作保留在前版导览验收（原路径 `docs/SCENARIO-GUIDE-VERIFICATION.md`，未随包提供）与前版回归输出（原路径 `docs/SCENARIO-GUIDE-REGRESSION.txt`，未随包提供），不作为本版布局的截图证据。

**此前四模块与视觉精修验收：** 498/498、桌面与 390px 截图属于场景导览之前的记录，见界面精修验收（原路径 `docs/VISUAL-POLISH-VERIFICATION.md`，未随包提供）、四模块验收记录（原路径 `docs/FRAMEWORK-VERIFICATION.md`，未随包提供）和历史回归日志（原路径 `docs/FRAMEWORK-REGRESSION.txt`，未随包提供）。这些历史截图不能代替新导览的浏览器验收。

**更早的历史验收记录：** 历史三步页面评审阶段的全量回归为 **439/439**，运行耗时 **42.238 秒**；普通与盲化模式均完成缺设备拒绝、设备返回、A 组合及 B 八组检查通过，并检查同轮结果保留、刷新恢复、跨轮只读、模式隔离、真实过期和窄屏固定操作栏。详细范围见三步凭证流程验收（原路径 `docs/CREDENTIAL-FLOW-VERIFICATION.md`，未随包提供）。**418/418** 和 `docs/credential-flow-screenshots/`（未随包提供）是同日较早的初版三步页面验收；该历史阶段的新增证据位于 `docs/credential-flow-review-screenshots/`（未随包提供），两者不能混用。**407/407** 属于此前五阶段协议主舞台的历史记录：当时完成普通 2.99 与盲化 3.25 TEST_USDC 两条浏览器流程，并检查逐步暂停、缺设备拒绝、挑战更新、锁设备失败恢复与输入失效，见历史协议主舞台验收（原路径 `docs/PROTOCOL-STAGE-VERIFICATION.md`，未随包提供）。**401/401** 属于 2026-10-08 较早的“六组业务过程”界面阶段：当时浏览器走通普通设备模式的默认 **2.99 TEST_USDC** 与自定义 **3.25 TEST_USDC** 订单，并检查输入失效、刷新、重置和锁设备拒绝，记录保留在历史核心演示验收（原路径 `docs/CORE-DEMO-VERIFICATION.md`，未随包提供）。**374/374** 是 2026-10-05 的历史完整回归记录；当时两种设备模式分别完成 **2.99 TEST_USDC** 本地付款及缺设备对照，见历史 W3C BBS 与 eSIM 验收（原路径 `docs/W3C-BBS-ESIM-VERIFICATION.md`，未随包提供）。较早手动舞台的 **342/342** 保留在历史手动演示验收（原路径 `docs/MANUAL-ESIM-VERIFICATION.md`，未随包提供）；论文支付验收（原路径 `docs/DBAC-PAYMENT-VERIFICATION.md`，未随包提供）的 **334/334**、统一演示验收（原路径 `docs/UNIFIED-DEMO-VERIFICATION.md`，未随包提供）的 **313/313** 与 **8/8** 也属于此前阶段，均不能作为本次改造重新运行的证据。

历史旧工作台曾按浏览器标签页保存最多 8 轮公开结果副本，其说明和旧模型仅作历史参考；当前 B/C 使用服务端实验运行记录，支付详情查看当前业务会话的交互记录。两者都不能把历史结果当成本次请求的验证结论。

官方参考：[x402](https://github.com/x402-foundation/x402) · [x402 A2A 绑定](https://github.com/x402-foundation/x402/blob/main/specs/transports-v2/a2a.md) · [jCardSim 上游](https://github.com/licel/jcardsim)
