# Gemini CLI to OpenAI API Proxy

这是一个独立的 Python 项目，旨在将 Google 的 `gemini-cli` 工具提供的功能，通过一个兼容 OpenAI API 的代理服务器暴露出来。它允许用户使用标准的 OpenAI 客户端库与 Google 的 Gemini 模型进行交互，同时支持直接调用原生 Gemini API。

> 本项目大量使用了https://github.com/gzzhongqi/geminicli2api 的代码，感谢原作者。

## 功能概览

- **双 API 支持**: 兼容 OpenAI API 和原生 Gemini API。
- **智能凭据管理**: 自动处理 OAuth2 凭据的获取、存储、刷新和轮转。
- **模型变体**: 支持 `search`、`nothinking`、`maxthinking` 等 Gemini 模型变体。
- **交互式配置**: 启动时引导用户完成 OAuth 流程。
- **高可用性**: 凭据池和自动重试机制确保服务稳定。

## 快速开始

### 1. 安装依赖

不一定需要安装 `gemini-cli` 工具，但安装后你可以通过 credentials_file 配置来读取 gemini-cli auth 后保存的凭据；

需要安装 Python 依赖；

```bash
# 在项目根目录下
pip install -r requirements.txt
```

### 2. 配置

创建一个 `config.json` 文件来配置代理服务器。如果未提供配置文件，将使用默认配置。

**示例 `config.json`:**

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 8888
  },
  "auth_password": "your_secret_password",
  "credentials_file": "credentials.json",
  "external_credentials_file": null,
  "project_id_map": {
    "user@example.com": "your-gcp-project-id"
  },
  "min_credentials": 1,
  "log_level": "INFO"
}
```

- `server`: 服务器监听地址和端口。
- `auth_password`: 用于 API 认证的密码。
- `credentials_file`: 存储 OAuth 凭据的文件路径。
- `external_credentials_file`: 外部凭据文件路径，用于导入。
- `project_id_map`: 用户邮箱到 GCP 项目 ID 的映射。
- `min_credentials`: 启动时所需的最小有效凭据数。
- `log_level`: 日志级别 (DEBUG, INFO, WARNING, ERROR)。

### 3. 启动服务器

```bash
# 使用默认配置 (config.json)
python -m gemini_cli_to_openai

# 使用自定义配置
python -m gemini_cli_to_openai -c /path/to/your/config.json
```

### 4. API 调用

服务器启动后，您可以使用以下端点：

- **OpenAI 兼容 API**:
  - `POST /v1/chat/completions`
  - `GET /v1/models`
- **原生 Gemini API**:
  - `GET /v1beta/models`
  - `POST /{...}` (代理所有其他 Gemini API 请求)

所有 API 端点都需要认证。您可以通过以下方式提供 `auth_password`:

- `Authorization: Bearer your_secret_password`
- `Authorization: Basic` (用户名任意，密码为 `your_secret_password`)
- `?key=your_secret_password`
- `x-goog-api-key: your_secret_password`

## 模型映射规则

本项目支持多种 Gemini 模型及其变体。模型名称在 OpenAI 和原生 Gemini API 中遵循不同的命名规则。

### 基础模型 (Base Models)

支持以下基础 Gemini 模型:

- `gemini-2.5-pro-preview-05-06`
- `gemini-2.5-pro-preview-06-05`
- `gemini-2.5-pro`
- `gemini-2.5-flash-preview-05-20`
- `gemini-2.5-flash-preview-04-17`
- `gemini-2.5-flash`

### 模型变体 (Variants)

通过在基础模型名称后添加特定后缀，可以调用模型的不同变体：

- **`-search`**: 启用 Google Search 工具。例如 `gemini-2.5-pro-search`。
- **`-nothinking`**: 禁用推理（Thinking）功能。例如 `gemini-2.5-pro-nothinking`。
- **`-maxthinking`**: 启用最大推理（Thinking）预算。例如 `gemini-2.5-pro-maxthinking`。

### 映射逻辑

- **OpenAI API**: 在 `/v1/chat/completions` 请求中，通过 `model` 字段指定模型名称（如 `gemini-2.5-pro-search`）。代理会自动将模型名称转换为对应的 Gemini 基础模型，并根据后缀设置 `tools` 和 `thinkingConfig`。
- **原生 Gemini API**: 直接使用基础模型名称（如 `models/gemini-2.5-pro`）或包含变体后缀的路径。代理会从路径中提取模型名称并应用相应的配置。

## 核心技术与逻辑规则

### 1. 凭据管理 (Credentials Management)

由 `credentials.py` 中的 `CredentialManager` 类负责。

- **持久化**: 凭据以简化格式（`access_token`, `refresh_token`, `token_type`, `expiry_date`）存储在 JSON 文件中。支持单个对象或对象数组格式，并根据 `refresh_token` 进行去重合并。
- **加载与初始化**: 启动时加载凭据，并为每个凭据获取 `email` 和 `project_id`（优先从配置映射，其次通过 API 发现）。
- **自动刷新**: 后台线程定期检查凭据，如果凭据即将过期（默认提前 600 秒），则使用 `refresh_token` 自动刷新。
- **轮转与重试**: 当发送 API 请求时，会从凭据池中选择一个可用凭据。如果收到 429 错误，该凭据会被暂时标记为 `EXHAUSTED`，然后切换到下一个可用凭据进行重试。

### 2. 数据格式转换

为了实现 OpenAI API 兼容性，项目在 `transformers_openai.py` 中实现了请求和响应的双向转换。

- **请求转换**: 将 OpenAI 的 `messages`、参数（`temperature`, `max_tokens` 等）映射到 Gemini 的 `contents` 和 `generationConfig`。处理 `system` 消息、图片输入、`search` 模型变体以及 `thinking` 配置。
- **响应转换**: 将 Gemini 的 `candidates` 响应（包括流式和非流式）转换为 OpenAI 的 `choices` 格式，处理 `finish_reason` 和 `reasoning_content`。

## 代码结构

```
gemini_cli_to_openai/
├── __main__.py          # 程序入口点，负责启动和配置
├── app.py               # FastAPI 应用装配和生命周期管理
├── auth.py              # 认证逻辑和 OAuth 流程
├── client.py            # Google API 客户端，处理请求转发和凭据轮转
├── config.py            # 配置管理、常量和模型定义
├── credentials.py       # 凭据管理器，负责加载、存储、刷新和轮转
├── routes_gemini.py     # 原生 Gemini API 路由
├── routes_openai.py     # OpenAI 兼容 API 路由
├── state.py             # 全局状态容器 (避免循环导入)
├── transformers_openai.py # OpenAI 和 Gemini 数据格式转换器
└── utils.py             # 通用工具函数

```
