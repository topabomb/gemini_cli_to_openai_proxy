# Gemini to OpenAI API Proxy (v2)

一个将 Google Gemini 封装为 OpenAI 兼容 API 的高性能、异步代理服务。

> **版本说明**: 本项目 (`gemini_cli_openaiapi_proxy`) 是对原有 `gemini_cli_to_openai` 的一次彻底重构，采用了现代化的 FastAPI 框架和全异步架构，在保持核心功能的基础上，大幅提升了性能、可维护性和可扩展性。

## 核心特性 (Core Features)

- **无缝 OpenAI API 兼容**: 零成本将现有 OpenAI 生态工具（如 ChatGPT Next Web, Ama, LobeChat 等）对接到 Gemini。
- **全异步高性能**: 基于 FastAPI 和 httpx 构建，提供高吞吐量和低延迟的异步处理能力。
- **网页端自动化认证**: 通过内置的 Web UI，轻松完成 Google OAuth2 认证流程，实现“一次登录，永久有效”。
- **高可用凭据池**: 支持配置多个凭据，通过自动轮转和“冷静期”机制，有效规避单一账户的速率限制 (Rate Limit)，大幅提升服务稳定性。
- **解锁 Gemini 高级功能**: 在兼容 API 中也能使用 Google Search、Thinking 等高级特性。
- **强大的管理与监控**: 内置 Web 管理界面和 API 端点，方便监控凭据状态和查询用量统计。
- **现代架构**: 清晰的分层设计（核心、服务、API），易于理解、维护和二次开发。

## 快速上手 (Getting Started)

### 1. 环境准备

- Python 3.8 或更高版本。

### 2. 安装依赖

```bash
# 在项目根目录下
pip install -r requirements.txt
```

### 3. 配置

在项目根目录创建一个 `config.json` 文件来配置代理服务器。下面是一个完整的配置范例：

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 8888
  },
  "auth_keys": ["your-secret-key-1", "your-secret-key-2"],
  "credentials_file": "credentials.json",
  "project_id_map": {
    "user1@gmail.com": "your-gcp-project-id-1",
    "user2@gmail.com": "your-gcp-project-id-2"
  },
  "log_level": "INFO",
  "request_timeouts": {
    "connect": 60,
    "read": 90
  },
  "usage_logging": {
    "enabled": true,
    "interval_sec": 300
  },
  "public_url": null,
  "min_credentials": 1,
  "admin_username": "admin",
  "admin_password": "your_secure_password"
}
```

> **⚠️ 注意：配置文件不会自动加载**
>
> 程序启动时**不会**自动加载当前目录下的 `config.json`。您必须使用 `-c` 或 `--config` 参数显式指定配置文件路径，否则将使用内置的默认配置。
>
> ```bash
> # 错误方式 (不会加载 config.json)
> python -m gemini_cli_openaiapi_proxy
>
> # 正确方式
> python -m gemini_cli_openaiapi_proxy -c config.json
> ```

#### 配置项说明

| 参数 | 类型 | 描述 | 默认值 |
| :--- | :--- | :--- | :--- |
| `server.host` | `string` | 服务器监听的主机地址。 | `"0.0.0.0"` |
| `server.port` | `integer` | 服务器监听的端口。 | `8889` |
| `auth_keys` | `list[string]` | 用于 API 认证的密钥列表。 | `["123456"]` |
| `credentials_file` | `string` | 存储 OAuth 凭据的 JSON 文件路径。 | `"credentials1.json"` |
| `project_id_map` | `dict` | 用户邮箱到 GCP 项目 ID 的映射。强烈建议配置此项以提高稳定性。 | `{}` |
| `min_credentials` | `integer` | 启动时所需的最小有效凭据数。如果可用凭据少于此值，将打印警告。 | `1` |
| `public_url` | `string` (可选) | **（推荐用于生产环境）** 服务的公开访问 URL。如果设置此项，OAuth 认证将使用此 URL 构建回调地址。<br>**⚠️ 重要:** 您填写的此 URL 加上 `/oauth2/callback` 的路径（例如 `https://your-domain.com/oauth2/callback`）**必须**被添加到您 Google Cloud Console 项目的 OAuth 2.0 客户端 ID 的“已获授权的重定向 URI”列表中。如果留空，服务将尝试从请求头中自动推断（适用于本地 `localhost` 测试）。 | `null` |
| `log_level` | `string` | 日志级别 (DEBUG, INFO, WARNING, ERROR)。 | `"debug"` |
| `request_timeouts` | `dict` | 对上游 Google API 的请求超时（秒）。 | `{"connect": 60, "read": 90}` |
| `usage_logging` | `dict` | 用量统计日志配置。 | `{"enabled": true, "interval_sec": 30}` |
| `admin_username` | `string` (可选) | 为管理后台设置一个用户名以启用密码保护。 | `null` |
| `admin_password` | `string` (可选) | 为管理后台设置一个密码。 | `null` |


### 4. 启动服务器

```bash
# 启动服务 (默认命令)
python -m gemini_cli_openaiapi_proxy run -c config.json

# (可选) 使用加密功能启动
python -m gemini_cli_openaiapi_proxy run -c config.json -ek "your-secret-key-here"
```

服务器启动后，您可以访问 `http://<your_host>:<your_port>` 来打开 Web 管理界面。

## 安全：加密凭据文件

为了保护您存储在 `credentials.json` 文件中的高权限 `refresh_token`，本项目提供了可选的加密功能。

### 1. 生成加密密钥

我们提供了一个内置命令来生成一个安全的加密密钥。

```bash
python -m gemini_cli_openaiapi_proxy generate-key
```

该命令会输出一个类似 `gAAAAABmI...` 的密钥。请**立即将此密钥备份到安全的地方**，例如您的密码管理器中。

> **⚠️ 警告：密钥丢失 = 数据丢失**
>
> 如果您丢失了这个密钥，加密后的 `credentials.json` 文件将**永久无法恢复**。您需要删除该文件并为所有账户重新进行网页授权。

### 2. 使用密钥启动服务

在启动服务时，通过 `-ek` 或 `--encryption-key` 参数提供您的密钥。

```bash
python -m gemini_cli_openaiapi_proxy run -c config.json --encryption-key "your-secret-key-here"
```

当您首次使用密钥启动时，程序会自动读取现有的明文 `credentials.json`，用您的密钥对其进行加密，然后将加密后的内容写回文件。此后的所有读写操作都将是加密的。

## API 使用指南 (Usage)

### 认证方式

所有 API 端点都需要认证。您可以通过以下任意一种方式提供 `auth_keys` 中配置的密钥:

- **Bearer Token**: `Authorization: Bearer your_secret_key`
- **Basic Auth**: `Authorization: Basic ...` (用户名任意，密码为 `your_secret_key`)
- **Query Parameter**: `?key=your_secret_key`
- **Header**: `x-goog-api-key: your_secret_key`

### API 端点

#### OpenAI 兼容 API
- `POST /v1/chat/completions`
- `GET /v1/models`

#### 原生 Gemini API
- `GET /v1beta/models`
- `POST /v1beta/models/{model}:streamGenerateContent`
- ... (代理所有其他 Gemini API 请求)

#### 管理与监控 API
- `GET /`: 访问 Web 管理界面。
- `GET /oauth2/login`: （通过 Web 界面点击）开始 OAuth2 认证流程。
- `GET /admin/credentials`: 以 JSON 格式获取所有凭据的详细状态。
- `GET /admin/usage`: 以 JSON 格式获取详细的用量统计快照。
- `GET /health`: 健康检查端点。

## 工作原理 (How It Works)

新版代理采用基于 FastAPI 的现代化分层架构：

### 1. 服务层 (`services/`)
- **`CredentialManager`**: 凭据管理器。负责从文件加载、持久化凭据。内置后台任务，使用 `refresh_token` 自动刷新即将过期的 `access_token`。当请求失败时，它能根据失败原因（如 429）将凭据置于临时“冷静期”，实现高可用轮转。
- **`GoogleApiClient`**: Google API 客户端。基于 `httpx.AsyncClient` 实现全异步请求。它从 `CredentialManager` 获取可用凭据，并包含完整的请求重试逻辑。
- **`UsageTracker`**: 用量追踪器。在内存中精确统计每个 `auth_key`、每个 `credential` 下每个模型的请求次数和 token 消耗。后台任务会定期将详细的多级统计报告打印到日志中。

### 2. API 层 (`api/`)
- **路由 (`routes/`)**: 定义了所有对外暴露的 API 端点，包括 OpenAI 兼容 API、原生 Gemini 代理和管理 API。
- **依赖注入 (`dependencies.py`)**: 利用 FastAPI 的依赖注入特性，将服务实例（如 `CredentialManager`）提供给 API 路由，实现控制反转和松耦合。

### 3. 核心层 (`core/`)
- **配置 (`config.py`)**: 集中管理应用的所有配置项和默认值。
- **生命周期 (`lifespan.py`)**: 在应用启动时，负责初始化所有服务和后台任务；在应用关闭时，负责优雅地释放资源。

## 代码结构

```
gemini_cli_openaiapi_proxy/
├── __main__.py          # 程序入口点
├── app.py               # FastAPI 应用组装器
├── main.py              # 命令行解析与服务启动
├── api/                 # API 表现层
│   ├── dependencies.py
│   ├── security.py
│   └── routes/
│       ├── admin.py
│       ├── gemini.py
│       └── openai.py
├── core/                # 核心组件
│   ├── config.py
│   ├── lifespan.py
│   ├── logging_config.py
│   └── models.py
├── services/            # 业务逻辑层
│   ├── credential_manager.py
│   ├── google_client.py
│   └── usage_tracker.py
└── utils/               # 通用工具
    └── transformers.py
