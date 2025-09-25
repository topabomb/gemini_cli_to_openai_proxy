# Qwen-Code OAuth2 与 LLM API 交互演示项目

## 项目概述

本项目是对 Qwen-Code 项目的 OAuth2 认证流程和 LLM API 交互流程的深入分析和演示。通过 Python 实现，模拟了 Qwen CLI 的核心功能，包括 OAuth2 设备授权流程和 API 调用。

## Qwen-Code 项目分析

### OAuth2 流程

Qwen-Code 项目使用 OAuth2 设备授权流程（Device Authorization Flow）进行认证，具体流程如下：

1. 设备代码请求：
   - 客户端向 `https://chat.qwen.ai/api/v1/oauth2/device/code` 发起请求
   - 获取设备代码、用户代码和授权 URL

2. 用户授权：
   - 用户访问授权 URL 并使用用户代码进行授权
   - 用户在浏览器中完成身份验证

3. 令牌轮询：
   - 客户端定期向令牌端点轮询访问令牌
   - 成功后获取访问令牌、刷新令牌和资源 URL

4. 令牌使用：
   - 使用访问令牌调用 Qwen API
   - 资源 URL (`resource_url`) 用于确定 API 端点（在我们的案例中是 `portal.qwen.ai`）

### 关键代码位置

- OAuth2 实现：`packages/core/src/qwen/qwenOAuth2.ts`
- 令牌管理：`packages/core/src/qwen/sharedTokenManager.ts`
- API 内容生成器：`packages/core/src/qwen/qwenContentGenerator.ts`
- DashScope 兼容提供者：`packages/core/src/core/openaiContentGenerator/provider/dashscope.ts`

### LLM API 交互流程

1. 端点构建：
   - 如果有 `resource_url`，使用该 URL 作为基础端点
   - 否则使用默认的 DashScope 端点 `https://dashscope.aliyuncs.com/compatible-mode/v1`
   - 确保 URL 格式正确（添加协议和 `/v1` 后缀）

2. 请求构建：
   - 使用访问令牌进行身份验证
   - 设置适当的请求头（User-Agent、内容类型等）
   - 构建符合 OpenAI 兼容格式的请求体

3. 响应处理：
   - 处理流式和非流式响应
   - 解析 JSON 响应数据
   - 提取模型生成的内容

### 可使用的模型清单

经过验证，以下模型在当前环境中可用（具体结果因环境而异，详见“验证结果”与本地验证说明）：

- `qwen3-coder-plus` - 主要的编码模型
- `qwen3-coder-flash` - 更快、更经济的编码模型
- `coder-model` - 通用编码模型
- `vision-model` - 通用视觉模型

以下模型在部分环境中可能不可用：

- `qwen-vl-max-latest` - 视觉模型（在某些环境不支持）
- `qwen-vl-plus` - 视觉模型（在某些环境不支持）

## Demo 项目结构

### 文件结构

```
demo/
├── __init__.py
├── config.py            # 配置常量（OAuth 端点、User-Agent、轮询参数等）
├── oauth2_client.py     # OAuth2 客户端实现（设备码 + PKCE + 刷新）
├── oauth.py             # OAuth2 授权流程（演示脚本，写入凭据）
├── chat.py              # LLM 交互（流式/非流式、模型列表）
├── model_validator.py   # 模型验证工具（向各模型发起测试请求）
├── pkce.py              # PKCE 工具（code_verifier / code_challenge）
├── requirements.txt     # 依赖清单（使用 httpx 等）
├── .gitignore           # 忽略 demo/oauth_creds.json
└── README.md            # 本文件
```

说明：
- 运行授权后会生成 `demo/oauth_creds.json`（访问令牌、刷新令牌、resource_url 等），该文件为运行产物，已通过 `.gitignore` 忽略。

### 功能说明

#### OAuth2 授权流程 (oauth.py)

- 实现完整的设备授权流程
- 使用 PKCE (Proof Key for Code Exchange) 增强安全性
- 获取并保存访问令牌、刷新令牌和资源 URL

#### LLM 交互 (chat.py)

- 支持流式和非流式 API 调用
- 支持模型选择功能
- 命令行接口，使用子命令方式：
  - `chat` - 发送提示到 Qwen
  - `list-models` - 列出可用模型
- 自动检测令牌是否即将过期；若有刷新令牌会自动刷新并回写凭据

#### 模型验证 (model_validator.py)

- 验证所有已知模型的可用性
- 发送测试请求以确认模型是否可用

### 关键逻辑

#### OAuth2 客户端实现

`oauth2_client.py` 包含 QwenOAuth2Client 类，实现以下功能：

- 设备代码请求（含 PKCE code_challenge）
- 授权轮询（含 PKCE code_verifier）
- 刷新令牌
- 凭据管理

#### API 交互逻辑

`chat.py` 中的 API 交互逻辑包括：

- 根据 `resource_url` 构建正确的 API 端点
- 支持流式和非流式请求
- 错误处理和响应解析
- 使用刷新令牌在调用前自动续期

#### 配置管理

`config.py` 包含必要的配置常量，如 User-Agent 字符串等。

## 使用方法

### 安装依赖

```bash
pip install -r demo/requirements.txt
```

### 运行 OAuth2 授权

```bash
python -m demo.oauth
```

### 与 Qwen 交互

```bash
# 基本聊天
python -m demo.chat chat -p "你的提示"

# 使用流式响应
python -m demo.chat chat -p "你的提示" -s

# 使用特定模型
python -m demo.chat chat -p "你的提示" -m qwen3-coder-plus

# 同时使用流式和特定模型
python -m demo.chat chat -p "你的提示" -s -m qwen3-coder-flash
```

### 列出可用模型

```bash
python -m demo.chat list-models
```

## 技术细节

### API 端点格式化

遵循 `QwenContentGenerator.getCurrentEndpoint()` 方法的逻辑：

1. 如果 `resource_url` 以 "http" 开头，直接使用
2. 否则添加 "https://" 前缀
3. 如果 URL 不以 "/v1" 结尾，则添加 "/v1" 后缀

### 认证头

所有 API 请求都包含以下认证头：

- `Authorization: Bearer {access_token}`
- `User-Agent: {user_agent}`
- `Content-Type: application/json`

### 请求负载格式

使用 OpenAI 兼容格式：

```json
{
  "model": "model_name",
  "messages": [
    {
      "role": "user",
      "content": "prompt_content"
    }
  ],
  "stream": true/false
}
```

## 验证结果

模型可用性会因账号权限、区域和后端配置而变化。建议运行以下命令以获得本地权威结果：

```bash
python -m demo.model_validator
```

若在你当前环境中验证的结果与 README 示例不同，以本地验证结果为准。