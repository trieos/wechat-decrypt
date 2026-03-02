# WeChat 4.0 Database Decryptor

微信 4.0 本地数据库解密工具，支持 **Windows** 和 **macOS**。从运行中的微信进程内存提取加密密钥，解密所有 SQLCipher 4 加密数据库，并提供实时消息监听和 AI 集成。

## 原理

微信 4.0 使用 SQLCipher 4 加密本地数据库：
- **加密算法**: AES-256-CBC + HMAC-SHA512
- **KDF**: PBKDF2-HMAC-SHA512, 256,000 iterations
- **页面大小**: 4096 bytes, reserve = 80 (IV 16 + HMAC 64)
- **每个数据库有独立的 salt 和 enc_key**

WCDB (微信的 SQLCipher 封装) 会在进程内存中缓存派生后的 raw key，格式为 `x'<64hex_enc_key><32hex_salt>'`。本工具通过扫描进程内存中的这种模式，匹配数据库文件的 salt，并通过 HMAC 验证来提取正确的密钥。

- **Windows**: 通过 `kernel32.dll` 的 `ReadProcessMemory` API 扫描内存
- **macOS**: 通过 Mach VM API (`task_for_pid` + `mach_vm_read`) 扫描内存

## 使用方法

### 环境要求

| | Windows | macOS |
|---|---------|-------|
| 系统 | Windows 10/11 | macOS 13+ (ARM64/x86_64) |
| Python | 3.10+ | 3.10+ |
| 微信 | 4.0+ (正在运行) | 4.0+ (正在运行) |
| 权限 | 管理员权限 | sudo (或终端拥有 Full Disk Access) |

### 安装依赖

```bash
pip install pycryptodome
pip install mcp  # 可选，MCP Server 需要
```

### 1. 配置

```bash
cp config.example.json config.json
```

**Windows:**
```json
{
    "db_dir": "C:\\Users\\你的用户名\\Documents\\xwechat_files\\你的微信ID\\db_storage",
    "keys_file": "all_keys.json",
    "decrypted_dir": "decrypted",
    "wechat_process": "Weixin.exe"
}
```

**macOS:**
```json
{
    "db_dir": "/Users/你的用户名/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/你的微信ID/db_storage",
    "keys_file": "all_keys.json",
    "decrypted_dir": "decrypted",
    "wechat_process": "WeChat"
}
```

> **如何找到 `db_dir`**: 微信设置 → 文件管理 → 打开文件夹，找到 `db_storage` 子目录。  
> macOS 也可以用 `ls ~/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/` 查看。

### 2. 提取密钥

确保微信正在运行。

**Windows** — 以管理员权限运行：
```bash
python find_all_keys.py
```

**macOS** — 需要两步：

```bash
# 第一步：扫描微信进程内存，提取 key/salt 对
sudo python3 find_all_keys_macos.py

# 第二步：将 key/salt 与实际数据库文件匹配 + HMAC 校验
sudo python3 match_keys_macos.py

# 第三步：复制结果到项目目录
cp /tmp/wechat_all_keys.json all_keys.json
```

> **为什么需要 sudo?**  
> macOS 的 `task_for_pid()` 即使开启了 DevToolsSecurity 也需要 root 权限（错误码 5）。  
> 读取 WeChat 沙箱内的 DB 文件也需要 Full Disk Access 或 sudo。

密钥保存到 `all_keys.json`。

### 3. 解密数据库

```bash
python decrypt_db.py          # Windows
sudo python3 decrypt_db.py    # macOS (无 FDA 时需要 sudo)
```

解密后的数据库保存在 `decrypted/` 目录，可以直接用 SQLite 工具打开。

### 4. 实时消息监听

#### Web UI (推荐)

```bash
python monitor_web.py          # Windows
sudo python3 monitor_web.py    # macOS
```

打开 http://localhost:5678 查看实时消息流。

- 30ms 轮询 WAL 文件变化 (mtime)
- 检测到变化后全量解密 + WAL patch (~70ms)
- SSE 实时推送到浏览器
- 总延迟约 100ms

#### 命令行

```bash
python monitor.py
```

每 3 秒轮询一次，在终端显示新消息。

### 5. MCP Server (Claude AI 集成)

将微信数据查询能力接入 [Claude Code](https://claude.ai/claude-code)，让 AI 直接读取你的微信消息。

```bash
pip install mcp
```

注册到 Claude Code：

```bash
# Windows
claude mcp add wechat -- python C:\Users\你的用户名\wechat-decrypt\mcp_server.py

# macOS
claude mcp add wechat -- sudo python3 /path/to/wechat-decrypt/mcp_server.py
```

或手动编辑 `~/.claude.json`：

```json
{
  "mcpServers": {
    "wechat": {
      "type": "stdio",
      "command": "sudo",
      "args": ["python3", "/path/to/wechat-decrypt/mcp_server.py"]
    }
  }
}
```

注册后在 Claude Code 中即可使用以下工具：

| Tool | 功能 |
|------|------|
| `get_recent_sessions(limit)` | 最近会话列表（含消息摘要、未读数） |
| `get_chat_history(chat_name, limit)` | 指定聊天的消息记录（支持模糊匹配名字） |
| `search_messages(keyword, limit)` | 全库搜索消息内容 |
| `get_contacts(query, limit)` | 搜索/列出联系人 |
| `get_new_messages()` | 获取自上次调用以来的新消息 |

前置条件：需要先完成步骤 1-2（配置 + 提取密钥）。

**[查看使用案例 →](USAGE.md)**

## 文件说明

| 文件 | 说明 | 平台 |
|------|------|------|
| `config.py` | 配置加载器 | 通用 |
| `find_all_keys.py` | Windows 密钥提取 (kernel32.dll) | Windows |
| `find_all_keys_macos.py` | macOS 密钥提取 (Mach VM API) | macOS |
| `match_keys_macos.py` | macOS 密钥匹配 + HMAC 校验 | macOS |
| `decrypt_db.py` | 全量解密所有数据库 | 通用 |
| `mcp_server.py` | MCP Server，让 Claude AI 查询微信数据 | 通用 |
| `monitor_web.py` | 实时消息监听 (Web UI + SSE) | 通用 |
| `monitor.py` | 实时消息监听 (命令行) | 通用 |
| `latency_test.py` | 延迟测量诊断工具 | 通用 |

## macOS 适配说明

### 与 Windows 版的差异

WeChat 4.0 在 macOS 和 Windows 上使用**完全相同的加密方案**（SQLCipher 4, AES-256-CBC, HMAC-SHA512）。差异仅在于：

| 方面 | Windows | macOS |
|------|---------|-------|
| 密钥提取 | `kernel32.dll` ReadProcessMemory | Mach VM API (`task_for_pid` + `mach_vm_read`) |
| 数据目录 | `C:\Users\...\Documents\xwechat_files\` | `~/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/` |
| 文件访问 | 管理员权限即可 | 需要 Full Disk Access 或 sudo（macOS 沙箱保护） |
| 进程名 | `Weixin.exe` | `WeChat` |

### macOS 密钥提取原理

`find_all_keys_macos.py` 使用 Python ctypes 直接调用 macOS 的 Mach VM API：

1. **`task_for_pid(pid)`** — 获取 WeChat 进程的 Mach task port
2. **`mach_vm_region()`** — 枚举所有可读写内存区域（堆内存）
3. **`mach_vm_read()`** — 按 8MB 分块读取内存
4. **模式匹配** — 搜索 `x'<64位hex_key><32位hex_salt>'` 格式的字符串
5. **`match_keys_macos.py`** — 将找到的 salt 与实际 .db 文件的前 16 字节比对
6. **HMAC 校验** — 用 `PBKDF2(key, salt⊕0x3a, 2, 32)` 派生 mac_key，验证第一页 HMAC

### macOS Full Disk Access

WeChat 的数据文件在 macOS 沙箱容器内（`~/Library/Containers/com.tencent.xinWeChat/`），默认受系统保护。有两种方式获取访问：

**方式一：授权 Full Disk Access（推荐）**
1. 系统设置 → 隐私与安全性 → 完全磁盘访问权限
2. 点 + 添加你使用的终端 App（如 iTerm2、Ghostty、Terminal 等）
3. **完全退出并重启终端 App**（必须重启才生效）

授权后所有操作无需 sudo。

**方式二：使用 sudo**

所有涉及读取 WeChat 数据文件的命令前加 `sudo`：
```bash
sudo python3 find_all_keys_macos.py
sudo python3 match_keys_macos.py
sudo python3 decrypt_db.py
sudo python3 monitor_web.py
```

## 技术细节

### WAL 处理

微信使用 SQLite WAL 模式，WAL 文件是**预分配固定大小** (4MB)。检测变化时：
- 不能用文件大小 (永远不变)
- 使用 mtime 检测写入
- 解密 WAL frame 时需校验 salt 值，跳过旧周期遗留的 frame

### 数据库结构

解密后包含约 26-34 个数据库（macOS 上可能更多）：
- `session/session.db` - 会话列表 (最新消息摘要)
- `message/message_*.db` - 聊天记录（按哈希分表，每个联系人/群有独立的 `Msg_<md5>` 表）
- `contact/contact.db` - 联系人
- `media_*/media_*.db` - 媒体文件索引
- 其他: head_image, favorite, sns, emoticon 等

### 消息表结构

每个消息存储在 `Msg_<md5(username)>` 表中：

| 字段 | 说明 |
|------|------|
| `local_id` | 本地消息 ID |
| `server_id` | 服务器消息 ID |
| `local_type` | 消息类型 (1=文本, 3=图片, 34=语音, 43=视频, 49=链接/文件, 10000=系统) |
| `create_time` | Unix 时间戳 |
| `message_content` | 消息内容（文本/XML） |
| `real_sender_id` | 发送者 ID |

## 免责声明

本工具仅用于学习和研究目的，用于解密**自己的**微信数据。请遵守相关法律法规，不要用于未经授权的数据访问。
