# BindCart 评审交付版

BindCart 将 W3C bbs-2023 凭证、BBS-BLS / BBS-BlindBLS 软件设备绑定、持有者 Ed25519 请求签名、Owner 单笔授权与 x402 本地测试链付款连接起来。交付版为 0.5.1。商城与认证控制台使用同一组实际服务；TEST_USDC 为本地测试代币。

## 运行完整交付包

在上级目录运行 `Start-Windows.cmd` 或 `Start-Mac.command`，退出使用对应 `Stop` 脚本。依赖和三套 Node 运行时随包提供，无需 Java、npm 安装、外部账号或在线服务。

Windows 目标为 Windows 10/11 x64。macOS 目标为 13.5+，支持 arm64 与 x64。测试结果见作品报告。

## 从纯源码安装

保留完整 BindCart 目录结构，其中包含 `portable.mjs`、`verify-package.mjs` 和本 app 目录。安装 Node.js 22.13+ 与 npm，推荐使用交付包同版本 Node.js 24.19.0。在 app 目录执行：

```sh
npm ci
npm run check
npm start
```

首次安装依赖需要访问 npm 官方仓库。不要用 `npm install` 更新锁定版本。`npm start`、`npm run start:dual` 与双击入口均使用 `portable.mjs → launch-dual.mjs`，自动选择端口并打开介绍页。

```sh
npm run start:headless
npm stop
```

headless 仅不打开浏览器，仍启动完整服务。终端不打印会话权限参数；需要交互时重新运行正常 Start 入口。直接运行 `node launch-dual.mjs` 是测试/开发底层入口，不用于评委日常启动。

## 测试

从 app 目录运行：

```sh
npm test
npm run test:delivery
npm run test:dbac
npm run test:x402
npm run styles:check
```

`npm test` 通过 JavaScript 枚举测试文件，避免 Windows cmd 对通配符的差异。主线测试不需要 Java。服务测试会监听本机临时端口，使用独立临时账本与测试链，不读取既有 app/var。

完整包无需 npm，可在 BindCart 根目录用对应内置 Node 直接运行 `app/scripts/test.mjs`。双击 `Check-Windows.cmd` / `Check-Mac.command` 会执行文件完整性与关键交付流程验收。

Windows 完整包可在 BindCart 根目录执行：

```bat
runtime\win-x64\node.exe app\scripts\test.mjs
```

Windows 不适用 POSIX `0600/0700` 权限位断言，相关子测试会明确跳过；文件访问权限由 Windows ACL 决定。符号链接用例需要相应的创建权限，无法创建样本时会记录跳过原因；启用开发者模式或配置权限后可补跑。

`test:delivery` 包括：当前主线启动、商城购物、未授权拒绝、Owner 明确批准、实际链上测试付款、商户确认、重试与查询不重复扣款、复制/撤销实验，以及普通与盲化两种模式的三阶段付款和新证明重试幂等性。商城界面固定为普通模式；盲化对比通过核心接口与专项测试复现。

浏览器自动验收另外需要已安装的 Chrome 或 Edge，`playwright-core` 不包含浏览器。共享启动器默认依次尝试 Edge、Chrome、匹配版本的 Chromium，可指定 `PLAYWRIGHT_BROWSER_CHANNEL` 或 `PLAYWRIGHT_BROWSER_EXECUTABLE_PATH`，两者不可同时设置。

## 代码位置

| 目录或文件 | 用途 |
|---|---|
| `launch-dual.mjs` | 主线多进程启动与停止 |
| `lib/dbac/` | 设备绑定凭证、持有者签名、状态核验、支付会话 |
| `lib/w3c-bbs.mjs` | 标准 bbs-2023 签发与派生验证 |
| `lib/x402-payment.mjs` | 本地链、测试钱包与付款回执 |
| `lib/storefront/` | 商城订单、商户确认、逐步控制台与记录 |
| `public/intro.*` | 技术介绍页 |
| `public/dual.*`、`public/mechanism.*`、`public/store/` | 商城与认证控制台 |
| `test/` | 当前交付版回归测试 |
| `scripts/payment-consistency.mjs` | 普通/盲化真实付款与幂等核验 |
| `agent-a.mjs`、`launch-dbac.mjs` | 无 Java 的机制诊断及接口测试支持 |

当前交付版使用 Node 软件 eSIM，包含协议、账本、授权服务、商城页面组件及对应的单元和集成测试。

## 数据和实现范围

主线设备是独立 Node BLS12-381 软件签名服务，不是运营商 eUICC，也不声称提供硬件不可提取保证。每阶段核对标准 VC、设备贡献、持有者签名、订单/挑战绑定及可信本地凭证状态；Owner 明确批准后才允许钱包签名。

`app/var` 保存本副本生成的订单、账本、钱包和临时权限。发布包不含运行状态。软件设备身份与会话权限在重启时重新生成；历史已结算记录可查询，未完成的旧授权不会自动续用。结算结果未知时必须核对原交易，不能自动创建新付款。

`DUAL_STATE_DIR`、`DUAL_RUNTIME_PATH` 和 `DUAL_PORT=0` 供隔离测试使用。启动器自动使用独立本机端口；停止通过本副本的鉴权关闭接口执行。

本项目引入 Adyen 提供的 MyStore Demo 在线支付演示平台，作为系统的第三方展示与测试环境，用于模拟真实电商场景下的商品选购及支付流程。

该平台仅承担业务场景展示功能，不属于本项目的核心技术实现，也不计入团队自主研发成果。项目的核心功能及创新点由团队独立设计与实现。

第三方平台来源：https://www.mystoredemo.io/

交付包保留平台原始资源、依赖许可及字体许可。第三方来源和许可见上级 `THIRD-PARTY-NOTICES.txt`、`runtime/provenance.json` 及 `app/third-party`。
