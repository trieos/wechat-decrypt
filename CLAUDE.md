# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

WeChat 4.0 (Windows) 本地数据库解密工具。从运行中的微信进程内存提取 SQLCipher 4 加密密钥，解密数据库，提供实时消息监听和 MCP 查询接口。

**平台限制**: Windows only（依赖 `ctypes.windll` 读取进程内存），需管理员权限 + 运行中的微信。

## Commands

```bash
# 安装依赖
pip install pycryptodome zstandard mcp

# 核心工作流（按顺序执行）
python find_all_keys.py          # 1. 提取数据库密钥 → all_keys.json
python decrypt_db.py             # 2. 全量解密 → decrypted/
python monitor_web.py            # 3. Web 实时监听 → http://localhost:5678
python monitor.py                # 3. 或 CLI 监听（3s 轮询）

# 图片解密（V2 格式需额外密钥）
python find_image_key_monitor.py # 持续扫描进程内存提取图片 AES 密钥
python find_image_key.py         # 单次扫描版

# MCP Server（Claude AI 集成）
python mcp_server.py             # stdio 模式，由 Claude Code 调用
```

无自动化测试、无 lint 配置、无构建步骤。

## Architecture

### 加密体系

所有模块共享同一套 SQLCipher 4 解密原语：
- **页面**: 4096 bytes，reserve = 80 (IV 16 + HMAC-SHA512 64)
- **KDF**: `PBKDF2-HMAC-SHA512(enc_key, salt ^ 0x3a, iterations=2)` → mac_key
- **解密**: `AES-256-CBC(enc_key, iv, ciphertext)` per page
- **验证**: HMAC-SHA512(mac_key, page_content + page_number_le)
- 每个 .db 有独立的 enc_key + salt，存储在 `all_keys.json`

### 模块依赖关系

```
config.py (配置加载)
    ↓
find_all_keys.py → all_keys.json (密钥文件)
    ↓
decrypt_db.py → decrypted/ (明文 SQLite)
    ↓
┌─────────────────┬──────────────────┐
│ monitor.py      │ monitor_web.py   │ mcp_server.py
│ (CLI, 3s poll)  │ (SSE, 30ms poll) │ (FastMCP stdio)
└─────────────────┴──────────────────┘
                        ↓
                  decode_image.py (图片 .dat 解密)
                        ↑
              find_image_key.py / find_image_key_monitor.py
```

### 关键设计决策

- **decrypt_page() 在多个模块中重复实现**（find_all_keys / decrypt_db / monitor / monitor_web），不是 import 关系。修改解密逻辑需同步多处。
- **WAL 检测用 mtime 而非文件大小**：微信 WAL 预分配 4MB 固定大小，文件大小永远不变。
- **WAL frame 需校验 salt**：WAL checkpoint 后旧 frame 仍存在于文件中，通过 salt1/salt2 匹配当前周期来跳过过期 frame。
- **monitor_web.py 的 MonitorDBCache**：缓存已解密的 DB，通过 mtime 检测 DB/WAL 变化后重新解密 + WAL patch。
- **Zstd 压缩**：session.db 的 summary 字段和 message 的 content 字段可能是 Zstd 压缩的，需 try-except 解压。

### 图片 .dat 三种格式

| 格式 | Magic | 加密 | 密钥 |
|------|-------|------|------|
| 旧 XOR | 无 | 单字节 XOR | 自动检测 (JPEG/PNG magic bytes) |
| V1 | `07 08 V1 08 07` | AES-128-ECB + XOR | 固定: `cfcd208495d565ef` |
| V2 | `07 08 V2 08 07` | AES-128-ECB + XOR | 从进程内存提取 |

### MCP Server Tools

`mcp_server.py` 暴露 5 个工具：`get_recent_sessions`, `get_chat_history`, `search_messages`, `get_contacts`, `get_new_messages`。优先读 `decrypted/` 预解密文件，回退到实时解密。

## Configuration

`config.json`（从 `config.example.json` 复制）：
- `db_dir`: 微信数据库目录（设置 → 文件管理可查看路径）
- `keys_file`: 密钥文件路径（默认 `all_keys.json`）
- `image_aes_key`: V2 图片 AES 密钥（由 find_image_key*.py 自动写入）

敏感文件（config.json, all_keys.json, decrypted/, decoded_images/）已在 .gitignore 中排除。

## Code Style

- 函数式为主，无类继承体系（decode_image.py 的 ImageResolver 是唯一的类）
- 所有模块独立运行，通过 config.py 共享配置
- 中文注释和输出，`print(..., flush=True)` 用于长时间操作的进度显示
