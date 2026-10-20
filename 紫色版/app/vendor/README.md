# A2A 固定版本规范副本

此目录保存上游 [a2aproject/A2A](https://github.com/a2aproject/A2A) 的 `v0.3.0` tag 原始文件。获取日期：2026-10-02。未改写文件内容、许可正文或其中的版权声明。

| 本地文件 | 固定版本来源 | 大小 | SHA-256 |
| --- | --- | ---: | --- |
| `a2a-v0.3.0.schema.json` | [specification/json/a2a.json](https://raw.githubusercontent.com/a2aproject/A2A/v0.3.0/specification/json/a2a.json) | 103940 字节 | `97d6e2435336836cd1d41dffacf83a1a97902b62b826ef14ec5704db85c95f17` |
| `A2A-LICENSE.txt` | [LICENSE](https://raw.githubusercontent.com/a2aproject/A2A/v0.3.0/LICENSE) | 11358 字节 | `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30` |

上游许可证为 Apache License 2.0，完整正文见 `A2A-LICENSE.txt`。本目录中的来源说明不表示 A2A 项目对本地 DID/VC 扩展的认证或背书。

Schema 使用 JSON Schema Draft 7。顶层只有 `$schema` 和 `definitions`；验证时必须引用相应定义，例如 `#/definitions/AgentCard`，不能仅验证根对象便认定 AgentCard 或消息符合协议。

协议扩展定义、固定版本语义和实现边界见 `../docs/A2A-PROFILE.md`。此副本只用于固定版本的结构核对；通过它不能独立证明跨 SDK 互操作性或安全性。
