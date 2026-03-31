# MEMORY.md

## 平台规则 (关键)
- **禁止直接修改 `openclaw.json`** 或运行 `openclaw doctor --fix`、`openclaw config fix` 等自动修复命令
- **配置修改必须通过 `gateway` 工具**：
  - `config.get` — 读取配置，返回 `{ raw: JSON5, hash: SHA256 }`
  - `config.patch` — 深度合并部分更新，需要 `raw` 参数和 `baseHash`

## 当前问题
- 飞书配对码已过期或无效
- **待处理**：用户需要在飞书中再次向机器人发送消息以生成新的配对码