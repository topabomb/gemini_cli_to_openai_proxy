# Gemini to OpenAI API Proxy



一个将 Google Gemini 封装为 OpenAI 兼容 API 的高性能代理

> 本项目大量使用了 https://github.com/gzzhongqi/geminicli2api 的代码，感谢原作者。

## 核心特性 (Core Features)

- **无缝 OpenAI API 兼容**: 零成本将现有 OpenAI 生态工具（如 ChatGPT Next Web, Ama, LobeChat 等）对接到 Gemini。
- **自动化认证**: 彻底告别繁琐的 Google Cloud OAuth2 流程，实现“一次登录，永久有效”。
- **高可用凭据池**: 支持配置多个凭据，通过自动轮转和重试机制，有效规避单一账户的速率限制 (Rate Limit)，大幅提升服务稳定性。
- **解锁 Gemini 高级功能**: 在兼容 API 中也能使用 Google Search、Thinking 等高级特性。

## 快速上手 (Getting Started)

### 1. 环境准备

- Python 3.8 或更高版本。

### 2. 安装依赖

```bash
# 在项目根目录下
pip install -r requirements.txt
```

> **说明**: 本项目可以独立运行，无需安装 Google 官方的 `gemini-cli`。但是，如果您已经安装并使用 `gemini-cli` 生成了凭据，本项目可以方便地复用这些凭据，省去重新认证的步骤。

### 3. 配置

在项目根目录创建一个 `config.json` 文件来配置代理服务器。

> **⚠️ 注意：配置文件不会自动加载**
>
> 程序启动时**不会**自动加载当前目录下的 `config.json`。您必须使用 `-c` 或 `--config` 参数显式指定配置文件路径，否则将使用内置的默认配置。
>
> ```bash
> # 错误方式 (不会加载 config.json)
> python -m gemini_cli_to_openai
>
> # 正确方式
> python -m gemini_cli_to_openai -c config.json
> ```

#### 配置项说明

| 参数                        | 类型           | 描述                                                                                                                            | 默认值        |
| --------------------------- | -------------- | ------------------------------------------------------------------------------------------------------------------------------- | ------------- |
| `server.host`               | `string`       | 服务器监听的主机地址。                                                                                                          | `"0.0.0.0"`   |
| `server.port`               | `integer`      | 服务器监听的端口。                                                                                                              | `8888`        |
| `auth_keys`                 | `list[string]` | 用于 API 认证的密钥列表。                                                                                                       | `["123456"]`  |
| `credentials_file`          | `string`       | 存储 OAuth 凭据的文件路径。                                                                                                     | `"credentials.json"` |
| `external_credentials_file` | `string`       |  用于导入的外部凭据文件路径。                                                                                             | `null`        |
| `project_id_map`            | `dict`         |  用户邮箱到 GCP 项目 ID 的映射。强烈建议配置此项以提高稳定性。                                                              | `{}`          |
| `min_credentials`           | `integer`      | 启动时所需的最小有效凭据数。                                                                                                    | `1`           |
| `log_level`                 | `string`       | 日志级别 (DEBUG, INFO, WARNING, ERROR)。                                                                                        | `"INFO"`      |
| `request_timeouts.connect`  | `integer`      |  对上游 Google API 建立连接的超时时间（秒）。                                                                             | `60`          |
| `request_timeouts.read`     | `integer`      |  对上游 Google API 等待响应的超时时间（秒）。                                                                             | `90`          |
| `usage_logging.enabled`     | `boolean`      |  是否启用用量统计日志。                                                                                                   | `true`        |
| `usage_logging.interval_sec`| `integer`      |  用量统计日志的输出间隔（秒）。                                                                                           | `30`          |

### 4. 启动服务器

```bash
# 使用自定义配置启动
python -m gemini_cli_to_openai -c config.json

# 使用自定义路径的配置
python -m gemini_cli_to_openai -c /path/to/your/config.json
```

## API 使用指南 (Usage)

### 认证方式

所有 API 端点都需要认证。您可以通过以下任意一种方式提供 `auth_keys` 中配置的密钥:

- **Bearer Token**: `Authorization: Bearer your_secret_key`
- **Basic Auth**: `Authorization: Basic ...` (用户名任意，密码为 `your_secret_key`)
- **Query Parameter**: `?key=your_secret_key`
- **Header**: `x-goog-api-key: your_secret_key`

### API 端点

- **OpenAI 兼容 API**:
  - `POST /v1/chat/completions`
  - `GET /v1/models`
- **原生 Gemini API**:
  - `GET /v1beta/models`
  - `POST /{...}` (代理所有其他 Gemini API 请求)

## 模型映射规则 (Model Mapping)

本项目支持多种 Gemini 模型及其变体。

### 支持的模型

- `gemini-2.5-pro-preview-05-06`
- `gemini-2.5-pro-preview-06-05`
- `gemini-2.5-pro`
- `gemini-2.5-flash-preview-05-20`
- `gemini-2.5-flash-preview-04-17`
- `gemini-2.5-flash`

对于上述每个基础模型，还支持以下变体：

- **`-search`**: 启用 Google Search 工具。例如 `gemini-2.5-pro-search`。
- **`-nothinking`**: 禁用推理（Thinking）功能。例如 `gemini-2.5-pro-nothinking`。
- **`-maxthinking`**: 启用最大推理（Thinking）预算。例如 `gemini-2.5-pro-maxthinking`。

在日志中打印的基础模型列表会包含这些变体。

## 工作原理 (How It Works)

### 1. 凭据管理器 (`credentials.py`)

- **持久化与加载**: 凭据以简化格式存储在 JSON 文件中，并根据 `refresh_token` 去重合并。
- **自动刷新**: 后台线程定期检查并使用 `refresh_token` 刷新即将过期的凭据。
- **轮转与重试**: 当 API 请求因速率限制 (429) 失败时，管理器会自动将当前凭据标记为暂时不可用，并切换到凭据池中的下一个可用凭据进行重试，确保服务的高可用性。

### 2. 数据格式转换器 (`transformers_openai.py`)

- **请求转换**: 将 OpenAI 的 `messages` 格式转换为 Gemini 的 `contents` 格式，并处理 `system` 消息、图片输入、`search` 及 `thinking` 等特殊配置。
- **响应转换**: 将 Gemini 的 `candidates` 响应（包括流式和非流式）转换为 OpenAI 的 `choices` 格式。

### 3. 架构风险与依赖

本项目的“开箱即用”特性依赖了一个非公开的 Google API (`cloudaicompanion.googleapis.com`) 来自动发现用户的 `project_id` 和获取 `thinking` 内容。

- **风险**: Google 可能随时更改或禁用此非公开 API，导致 `project_id` 自动发现功能失效。
- **建议**: 为了保证生产环境的稳定性，强烈建议在 `config.json` 中为所有用户**手动配置 `project_id_map`**，以消除对该非公开 API 的强依赖。

## 代码结构

```
gemini_cli_to_openai/
├── __init__.py          # 包初始化文件
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
├── usage.py             # 用量统计与日志记录
└── utils.py             # 通用工具函数
