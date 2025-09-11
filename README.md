# Gemini to OpenAI API Proxy (v2)

将 Google Gemini 封装为 OpenAI 兼容 API 的异步代理服务。

> **版本说明**: 本项目 (`gemini_cli_openaiapi_proxy`) 是对原有 `gemini_cli_to_openai` 的一次重构，采用了现代化的 FastAPI 框架和全异步架构，在保持核心功能的基础上，大幅提升了性能、可维护性和可扩展性。

## 核心特性 (Core Features)

- **无缝 OpenAI API 兼容**: 零成本将现有 OpenAI 生态工具（如 ChatGPT Next Web, Ama, LobeChat 等）对接到 Gemini。
- **全异步高性能**: 基于 FastAPI 和 httpx 构建，提供高吞吐量和低延迟的异步处理能力。
- **多样的认证方式**: 支持通过 Web 界面或纯命令行完成 Google OAuth2 认证，方便在不同环境下添加凭据。
- **高可用凭据池**: 支持配置多个凭据，通过自动轮转和智能健康检查机制，有效规避单一账户的速率限制 (Rate Limit)，大幅提升服务稳定性。
- **智能自愈**: 对检查失败的凭据采用非侵入式的 `SUSPECTED` 状态，在不影响使用的情况下促进其“自愈”，增强系统鲁棒性。
- **解锁 Gemini 高级功能**: 在兼容 API 中也能使用 Google Search 等高级特性。
- **强大的管理与监控**: 内置 Web 管理界面和 API 端点，方便监控凭据状态和查询用量统计。
- **现代架构**: 清晰的分层设计（核心、服务、API），易于理解、维护和二次开发。

## 快速上手：三步完成

### 第一步：安装与配置

#### 1. 环境准备
- Python 3.8 或更高版本。

#### 2. 安装依赖
```bash
# 在项目根目录下
pip install -r requirements.txt
```

#### 3. 创建配置文件
在项目根目录创建一个 `config.json` 文件。这是配置代理服务器所有行为的核心。

**完整配置范例:**
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
  "admin_password": "your_secure_password",

  "auth_client": {
    "proxy_url": "http://127.0.0.1:8888",
    "admin_username": "admin",
    "admin_password": "your_secure_password"
  }
}
```

### 第二步：启动服务器

```bash
# 启动服务
python -m gemini_cli_openaiapi_proxy run -c config.json
```
> **提示**: `run` 是默认命令，可以省略。例如：`python -m gemini_cli_openaiapi_proxy -c config.json`

服务器启动后，您可以继续下一步来添加 Google 凭据。

### 第三步：添加凭据

您可以通过以下两种方式之一来完成 Google OAuth2 认证并添加凭据。

#### 方式 A: 通过 Web 界面 (推荐)

这是最简单的方式，尤其适合在本地桌面环境使用。

1.  打开浏览器并访问您的服务地址，例如 `http://127.0.0.1:8888`。
2.  如果配置了管理员密码，请先登录。
3.  点击 "Actions" 下的 **"Start Authentication"** 链接。
4.  在弹出的 Google 授权页面中完成登录和授权。
5.  成功后，新凭据将被自动添加到服务器的凭据池中。

#### 方式 B: 通过命令行 (适用于服务器环境)

对于无法或不便使用 Web 界面的场景（例如在远程服务器上），`auth` 命令提供了一种纯命令行的方式。

1.  **前提条件**:
    *   确保代理服务器已经在运行。
    *   确保您的 `config.json` 文件中包含一个正确配置的 `auth_client` 部分。

2.  **运行命令**:
    ```bash
    python -m gemini_cli_openaiapi_proxy auth -c config.json
    ```

3.  **工作流程**:
    *   该命令会自动在本地启动一个临时的回调服务器。
    *   它会在控制台打印一个 Google 授权 URL，请复制此 URL 并在您的本地浏览器中打开。
    *   完成授权后，命令会自动捕获授权码，交换 `refresh_token`，发现 `project-id`，并安全地提交给代理服务器。

## API 使用指南

一旦您至少添加了一个有效凭据，就可以开始使用代理服务了。

### 1. API 认证

所有 API 端点都需要认证。您可以通过以下任意一种方式提供在 `config.json` 的 `auth_keys` 中配置的密钥:

- **Bearer Token**: `Authorization: Bearer your_secret_key`
- **Basic Auth**: `Authorization: Basic ...` (用户名任意，密码为 `your_secret_key`)
- **Query Parameter**: `?key=your_secret_key`
- **Header**: `x-goog-api-key: your_secret_key`

### 2. 调用模型

#### OpenAI 兼容模型

当您通过 `/v1/chat/completions` 端点访问时，可以使用以下模型名称。这些名称会被代理服务解析，以调用对应的原生 Gemini 模型并启用特定功能。

- **基础模型**: `gemini-2.5-pro-preview-05-06`, `gemini-2.5-pro`, `gemini-2.5-flash`
- **模型变体 (后缀)**:
  - `-search`: 启用 Google Search 工具 (例如: `gemini-2.5-pro-search`)。
  - `-nothinking`: 禁用模型的“思考过程”输出 (例如: `gemini-2.5-pro-nothinking`)。
  - `-maxthinking`: 启用最大的“思考过程”预算 (例如: `gemini-2.5-flash-maxthinking`)。

*注意：您可以根据 Google 的更新，在 `core/models.py` 的 `BASE_MODELS` 列表中添加或修改支持的模型。*

#### 原生 Gemini 模型

当您直接访问原生 Gemini API 端点时（如 `/v1beta/models/{model}:streamGenerateContent`），您可以使用 Google 官方支持的任何模型名称。

## 高级主题

### 1. 配置文件详解

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
| `auth_client` | `object` (可选) | **（新增）** 用于 `auth` 命令行工具的配置块。 | `null` |
| `auth_client.proxy_url` | `string` | 代理服务器的地址，`auth` 命令会将新凭据提交到此地址。 | |
| `auth_client.admin_username` | `string` | 用于 `auth` 命令认证的管理员用户名。 | |
| `auth_client.admin_password` | `string` | 用于 `auth` 命令认证的管理员密码。 | |

### 2. 安全：加密凭据文件

为了保护您存储在 `credentials.json` 文件中的高权限 `refresh_token`，本项目提供了可选的加密功能。

**生成加密密钥:**
```bash
python -m gemini_cli_openaiapi_proxy generate-key
```
> **⚠️ 警告：密钥丢失 = 数据丢失**
>
> 如果您丢失了这个密钥，加密后的 `credentials.json` 文件将**永久无法恢复**。

**使用密钥启动服务:**
```bash
python -m gemini_cli_openaiapi_proxy run -c config.json --encryption-key "your-secret-key-here"
```

### 3. 管理与监控 API

所有管理端点都受 `admin_username` 和 `admin_password` 保护。

- `GET /`: 访问 Web 管理界面。
- `GET /oauth2/login`: （通过 Web 界面点击）开始 OAuth2 认证流程。
- `GET /admin/credentials`: 以 JSON 格式获取所有凭据的详细状态。
- `GET /admin/usage`: 以 JSON 格式获取详细的用量统计快照。
- `GET /admin/credentials/{credential_id}/check`: 强制对单个凭据执行健康检查。
- `POST /admin/credentials/add`: （供 `auth` 命令使用）通过 API 添加一个新的凭据。
- `GET /health`: 健康检查端点。

## 工作原理 (How It Works)

新版代理采用基于 FastAPI 的现代化分层架构：

### 1. 服务层 (`services/`)
- **`CredentialManager`**: 凭据管理器。负责加载、持久化和轮转凭据。内置两个后台任务：
    1.  **刷新循环**: 自动使用 `refresh_token` 刷新即将过期或失效的凭据。
    2.  **健康检查循环**: 在系统空闲时，主动对凭据进行健康检查。检查失败的凭据会被标记为 `SUSPECTED`（可疑）状态，但仍可使用，若后续使用成功则会自动“自愈”。
- **`GoogleApiClient`**: Google API 客户端。基于 `httpx.AsyncClient` 实现全异步请求，并包含完整的请求重试逻辑。
- **`UsageTracker`**: 用量追踪器。在内存中精确统计每个 `auth_key` 和 `credential` 的用量。
- **`HealthCheckService`**: 健康检查器。封装了多种原子检查策略（如检查模型列表、用户信息等），并随机选取一种执行，以避免行为模式被预测。
- **`StateTracker`**: 系统状态追踪器。通过中间件实时追踪并发请求数，为健康检查提供“系统是否空闲”的判断依据。

### 2. 工具层 (`utils/`)
- **`credential_tools.py`**: 提供凭据序列化/反序列化，以及 `project-id` 发现的公共函数。
- **`sanitizer.py`**: 提供用于日志输出的敏感信息脱敏工具。

### 3. API 层 (`api/`)
- **路由 (`routes/`)**: 定义了所有对外暴露的 API 端点，包括 OpenAI 兼容 API、原生 Gemini 代理和管理 API。
- **依赖注入 (`dependencies.py`)**: 利用 FastAPI 的依赖注入特性，将服务实例（如 `CredentialManager`）提供给 API 路由，实现控制反转和松耦合。

### 3. 核心层 (`core/`)
- **配置 (`config.py`)**: 集中管理应用的所有配置项和默认值。
- **生命周期 (`lifespan.py`)**: 在应用启动时，负责初始化所有服务和后台任务；在应用关闭时，负责优雅地释放资源。
- **类型定义 (`types.py`)**: 定义了跨模块共享的核心数据类和类型别名，如 `ManagedCredential`。

## 代码结构

```
gemini_cli_openaiapi_proxy/
├── __main__.py          # 程序入口点
├── app.py               # FastAPI 应用组装器
├── main.py              # 命令行解析与服务启动
├── cli/                 # 命令行工具实现
│   └── local_auth_handler.py
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
│   ├── middleware.py
│   ├── models.py
│   └── types.py
├── services/            # 业务逻辑层
│   ├── credential_manager.py
│   ├── google_client.py
│   ├── health_checker.py
│   ├── state_tracker.py
│   └── usage_tracker.py
└── utils/               # 通用工具
    ├── credential_tools.py
    ├── sanitizer.py
    └── transformers.py
