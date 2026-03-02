# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

WeChat 4.0 本地数据库解密工具，支持 **Windows** 和 **macOS**。从运行中的微信进程内存提取 SQLCipher 4 加密密钥，解密数据库，提供实时消息监听和 MCP 查询接口。

需要管理员/sudo 权限 + 运行中的微信进程。

## Commands

```bash
# 安装依赖
pip install pycryptodome zstandard mcp

# === Windows 工作流 ===
python find_all_keys.py          # 1. 提取数据库密钥 → all_keys.json
python decrypt_db.py             # 2. 全量解密 → decrypted/
python monitor_web.py            # 3. Web 实时监听 → http://localhost:5678
python monitor.py                # 3. 或 CLI 监听（3s 轮询）

# === macOS 工作流（需 sudo）===
sudo python3 find_all_keys_macos.py    # 1a. Mach VM API 扫描进程内存
sudo python3 match_keys_macos.py       # 1b. 匹配密钥到数据库 + HMAC 校验 → all_keys.json
sudo python3 decrypt_db.py             # 2. 全量解密（无 Full Disk Access 时需 sudo）
sudo python3 monitor_web.py            # 3. Web 实时监听

# 图片解密（V2 格式需额外密钥）
python find_image_key_monitor.py # 持续扫描进程内存提取图片 AES 密钥
python find_image_key.py         # 单次扫描版

# MCP Server（Claude AI 集成，stdio 模式）
python mcp_server.py
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
find_all_keys.py (Windows)  ──┐
find_all_keys_macos.py (macOS)─┼→ all_keys.json (密钥文件)
match_keys_macos.py (macOS) ──┘
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

- **decrypt_page() 在多个模块中重复实现**（find_all_keys / decrypt_db / monitor / monitor_web / mcp_server），不是 import 关系。修改解密逻辑需同步所有模块。
- **mcp_server.py 不使用 config.py 的 `load_config()`**，而是直接读 config.json 并自行处理路径。其他模块（monitor_web.py, decrypt_db.py）通过 `from config import load_config` 使用。修改配置加载逻辑时需注意这个不一致。
- **WAL 检测用 mtime 而非文件大小**：微信 WAL 预分配 4MB 固定大小，文件大小永远不变。
- **WAL frame 需校验 salt**：WAL checkpoint 后旧 frame 仍存在于文件中，通过 salt1/salt2 匹配当前周期来跳过过期 frame。
- **monitor_web.py 的 MonitorDBCache**：缓存已解密的 DB，通过 mtime 检测 DB/WAL 变化后重新解密 + WAL patch。
- **Zstd 压缩**：session.db 的 summary 字段和 message 的 content 字段可能是 Zstd 压缩的（`WCDB_CT_message_content = 4` 表示压缩），需 try-except 解压。

### 数据库 Schema

消息表命名规则：`Msg_{md5(username)}` — 每个联系人/群聊的消息存储在以其 username 的 MD5 命名的表中。`Name2Id` 表存储 username ↔ rowid 映射，用于 real_sender_id 反查。

关键数据库：
- `session/session.db` — `SessionTable`：会话列表、未读数、最新消息摘要
- `message/message_*.db` — `Msg_{md5}` 表：聊天记录，`Name2Id` 表：用户映射
- `contact/contact.db` — `contact` 表：联系人（username, nick_name, remark, alias, description）
- `message/message_resource.db` — `MessageResourceInfo`：图片 MD5 等资源映射

macOS 与 Windows 的列名差异：`local_id` (Windows) vs `message_local_id` (macOS)，代码中通过 try-except 兼容。macOS 的 `local_type` 高位含 subtype，用 `& 0xFFFF` 取 base type。

### 图片 .dat 三种格式

| 格式 | Magic | 加密 | 密钥 |
|------|-------|------|------|
| 旧 XOR | 无 | 单字节 XOR | 自动检测 (JPEG/PNG magic bytes) |
| V1 | `07 08 V1 08 07` | AES-128-ECB + XOR | 固定: `cfcd208495d565ef` |
| V2 | `07 08 V2 08 07` | AES-128-ECB + XOR | 从进程内存提取 |

图片解密映射链：`message_*.db (local_id)` → `message_resource.db (packed_info 含 MD5)` → `.dat 文件路径` → 解密。macOS 回退方案：从 Msg 表的 `packed_info_data` 列直接提取 MD5。

### MCP Server Tools

`mcp_server.py` 暴露 7 个工具（FastMCP stdio transport）：

| Tool | 功能 |
|------|------|
| `get_recent_sessions` | 最近会话列表（摘要、未读数） |
| `get_chat_history` | 指定聊天的消息记录 |
| `search_messages` | 全库搜索消息内容 |
| `get_contacts` | 搜索/列出联系人 |
| `get_user_content` | 按联系人查询消息（支持仅对方发言） |
| `infer_contact_name` | 从聊天内容推断联系人真实姓名 |
| `get_new_messages` | 获取自上次调用以来的新消息 |
| `decode_image` | 解密指定图片（by local_id） |
| `get_chat_images` | 列出聊天中的图片消息 |

MCP Server 有自己的 `DBCache` 类，通过 mtime 检测变化并实时解密 + WAL patch。优先读 `decrypted/` 预解密文件（仅 contact.db），其余走实时解密。

## Configuration

`config.json`（从 `config.example.json` 复制）：
- `db_dir`: 微信数据库目录（设置 → 文件管理可查看路径）
- `keys_file`: 密钥文件路径（默认 `all_keys.json`）
- `decrypted_dir`: 解密输出目录（默认 `decrypted`）
- `wechat_process`: 进程名（Windows: `Weixin.exe`, macOS: `WeChat`）
- `image_aes_key`: V2 图片 AES 密钥（由 find_image_key*.py 自动写入）
- `wechat_base_dir`: 自动从 `db_dir` 推导（db_dir 的上级目录），用于定位图片 attach 目录

敏感文件（config.json, all_keys.json, decrypted/, decoded_images/）已在 .gitignore 中排除。

## Code Style

- 函数式为主，无类继承体系（`decode_image.py` 的 `ImageResolver` 和各 `DBCache` 是仅有的类）
- 所有模块独立运行，通过 config.py 共享配置（mcp_server.py 除外）
- 中文注释和输出，`print(..., flush=True)` 用于长时间操作的进度显示
- 路径分隔符需兼容 Windows（`\`）和 macOS（`/`），`_norm_key()` 函数处理 all_keys.json 中的 key 格式
