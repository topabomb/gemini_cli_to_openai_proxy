# Hook 系统设计文档

## 概述

本项目已成功将原有的 `UsageTracker` 替换为更灵活的 Hook 系统。新的 Hook 系统提供了在 LLM 代理请求的"请求开始"和"代理结束"两个关键时点插入自定义逻辑的能力。

## 核心组件

### 1. Hook 框架 (`core/hooks.py`)

#### `RequestContext` 类
包含请求的完整生命周期信息：
- `request_id`: 唯一请求标识
- `route`: 路由类型 ("openai.chat" 或 "gemini.native")
- `auth_key`: 认证密钥
- `model`: 目标模型
- `is_streaming`: 是否为流式请求
- `current_credential_id`: 当前使用的凭据ID
- `current_credential_email`: 当前使用的凭据邮箱
- `attempts`: 请求尝试记录列表 (`List[AttemptInfo]`)
- `usage_metadata`: 用量元数据字典
- `start_time`, `end_time`, `first_byte_time`: 时间戳
- `success`, `error`, `http_status`: 结果状态

#### `AttemptInfo` 类
记录单次请求尝试的信息：
- `cred_id`: 凭据ID
- `email_masked`: 脱敏后的邮箱地址
- `status_code`: HTTP状态码（可选）
- `reason`: 失败原因（可选）
- `timestamp`: 尝试时间戳

#### `HookManager` 类
负责管理和执行 Hook：
- `add_start_hook()`: 注册请求开始 Hook
- `add_end_hook()`: 注册请求结束 Hook
- `trigger_start()`: 触发所有开始 Hook
- `trigger_end()`: 触发所有结束 Hook

特性：
- **串行执行**: Hook 按注册顺序串行执行
- **异常隔离**: 单个 Hook 失败不影响其他 Hook 和主流程
- **超时保护**: 支持 Hook 执行超时控制
- **策略拦截**: 支持通过 `RequestDeniedError` 拒绝请求

### 2. 用量统计 Hook (`services/usage_hooks.py`)

#### `UsageStatsHook` 类
替代原有 `UsageTracker` 的功能：
- 统计成功/失败请求数
- 记录 token 使用量（总计、提示、候选、思考、缓存）
- 提供用量快照和聚合统计
- 支持后台日志记录任务

#### `PolicyEnforceHook` 类
用于请求策略检查：
- 当前为占位符实现
- 可扩展为速率限制、配额控制、黑白名单等功能

## 集成点

### 1. GoogleApiClient 集成
在 `send_gemini_request` 方法中：
1. 创建 `RequestContext`
2. 触发请求开始 Hook（可能包含策略检查）
3. 执行实际的 API 请求
4. 更新上下文状态和用量信息
5. 触发请求结束 Hook

### 2. 流式请求处理
- 在首个数据块时标记 `first_byte_time`
- 在生成器的 `finally` 块中确保触发结束 Hook
- 防止重复触发结束 Hook

### 3. 依赖注入
通过 FastAPI 的依赖注入系统提供：
- `get_hook_manager()`: 获取 Hook 管理器
- `get_usage_stats_hook()`: 获取用量统计 Hook

## 使用示例

### 添加自定义 Hook

```python
# 创建自定义 Hook
async def audit_hook(ctx: RequestContext):
    logger.info(f"Request {ctx.request_id} from {ctx.auth_key} for model {ctx.model}")

async def performance_hook(ctx: RequestContext):
    if ctx.end_time and ctx.start_time:
        duration = (ctx.end_time - ctx.start_time).total_seconds()
        logger.info(f"Request {ctx.request_id} completed in {duration:.2f}s")

# 注册 Hook
hook_manager.add_start_hook(audit_hook)
hook_manager.add_end_hook(performance_hook)
```

### 策略拦截示例

```python
async def rate_limit_hook(ctx: RequestContext):
    # 检查速率限制
    if is_rate_limited(ctx.auth_key):
        raise RequestDeniedError("Rate limit exceeded", 429)
```

## 优势

1. **灵活性**: 支持多个 Hook 串行执行，易于扩展
2. **解耦**: Hook 系统与核心业务逻辑分离
3. **可靠性**: 异常隔离确保系统稳定性
4. **完整性**: 覆盖流式和非流式请求的完整生命周期
5. **可观测性**: 提供丰富的上下文信息用于监控和分析


### API 兼容性
管理 API 端点保持不变：
- `GET /admin/usage` - 获取用量统计
- `POST /admin/usage/reset` - 重置用量统计

## 测试

运行 `test_hook_system.py` 来验证 Hook 系统的基本功能：

```bash
python test_hook_system.py
```

## 注意事项

1. Hook 执行时间应尽可能短，避免影响请求性能
2. Hook 中的异常会被捕获和记录，但不会中断主流程
3. 策略拦截 Hook 应谨慎使用，确保不会误杀正常请求
4. 流式请求的结束 Hook 只会触发一次，即使生成器异常退出
5. **重要**：`PolicyEnforceHook()` 构造函数不需要参数，而 `UsageStatsHook(credential_manager)` 需要传入凭据管理器
6. **类型安全**：确保 `ctx.attempts` 始终是 `List[AttemptInfo]` 类型，不要直接赋值为整数
7. **凭据追踪**：每次重试都会创建新的 `AttemptInfo` 对象添加到 `attempts` 列表中
