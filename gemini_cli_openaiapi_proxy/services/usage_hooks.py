"""
用量统计和策略检查 Hook 实现：
- 替代原有的 UsageTracker 功能
- 提供请求策略检查
- 提供用量统计和日志记录
- 支持凭据状态监控
"""

import json
import asyncio
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple

from ..core.hooks import RequestContext, RequestDeniedError, StartHook, EndHook

logger = logging.getLogger(__name__)

def _format_human_readable(num: int) -> str:
    """将数字转换为人类可读的 k/M 格式"""
    if num is None:
        return "0"
    if num < 1000:
        return str(num)
    if num < 1_000_000:
        return f"{num / 1000:.2f}k"
    return f"{num / 1_000_000:.2f}M"

@dataclass
class ModelStats:
    """每个模型的用量统计"""
    successful_requests: int = 0
    failed_requests: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    total_tokens: int = 0
    prompt_tokens: int = 0
    candidates_tokens: int = 0
    thoughts_tokens: int = 0
    cached_content_token_count: int = 0

class UsageStatsHook:
    """用量统计 Hook，替代原有的 UsageTracker"""
    
    def __init__(self, credential_manager):
        self.usage_data: Dict[str, Dict[str, Dict[str, ModelStats]]] = defaultdict(
            lambda: defaultdict(lambda: defaultdict(ModelStats))
        )
        self.credential_manager = credential_manager
        self.lock = asyncio.Lock()
        self.logging_task: Optional[asyncio.Task] = None
        self._last_logged_stats_str: Optional[str] = None
        self._last_logged_cred_status_str: Optional[str] = None

    async def on_request_end(self, ctx: RequestContext):
        """请求结束时记录用量统计"""
        async with self.lock:
            # 获取最后使用的凭据信息
            if not ctx.attempts:
                logger.warning(f"No credential attempts recorded for request {ctx.request_id}")
                return
                
            last_attempt = ctx.attempts[-1]
            cred_id = last_attempt.cred_id
            
            stats = self.usage_data[ctx.auth_key][cred_id][ctx.model]
            
            if ctx.success:
                stats.successful_requests += 1
                if ctx.usage_metadata:
                    stats.total_tokens += ctx.usage_metadata.get("totalTokenCount", 0)
                    stats.prompt_tokens += ctx.usage_metadata.get("promptTokenCount", 0)
                    stats.candidates_tokens += ctx.usage_metadata.get("candidatesTokenCount", 0)
                    stats.thoughts_tokens += ctx.usage_metadata.get("thoughtsTokenCount", 0)
                    stats.cached_content_token_count += ctx.usage_metadata.get("cachedContentTokenCount", 0)
            else:
                reason = ctx.error or "Unknown"
                stats.failed_requests[reason] += 1

    async def get_usage_snapshot(self) -> Dict[str, Any]:
        """获取用量数据的快照，用于 API 端点"""
        async with self.lock:
            def custom_serializer(obj):
                if isinstance(obj, (defaultdict, dict)):
                    return {k: custom_serializer(v) for k, v in obj.items()}
                if hasattr(obj, "__dict__"):
                    return custom_serializer(obj.__dict__)
                return obj
            return custom_serializer(self.usage_data)

    async def get_aggregated_usage_summary(self) -> Dict[str, Any]:
        """获取按模型聚合的用量数据快照，用于 API 端点，不暴露 auth_key"""
        async with self.lock:
            model_summary_stats: Dict[str, ModelStats] = defaultdict(ModelStats)
            for auth_stats in self.usage_data.values():
                for cred_stats in auth_stats.values():
                    for model_name, stats in cred_stats.items():
                        model_summary_stats[model_name].successful_requests += stats.successful_requests
                        model_summary_stats[model_name].total_tokens += stats.total_tokens
                        model_summary_stats[model_name].prompt_tokens += stats.prompt_tokens
                        model_summary_stats[model_name].candidates_tokens += stats.candidates_tokens
                        model_summary_stats[model_name].thoughts_tokens += stats.thoughts_tokens
                        for reason, count in stats.failed_requests.items():
                            model_summary_stats[model_name].failed_requests[reason] += count
            
            def custom_serializer(obj):
                if isinstance(obj, (defaultdict, dict)):
                    return {k: custom_serializer(v) for k, v in obj.items()}
                if hasattr(obj, "__dict__"):
                    return custom_serializer(obj.__dict__)
                return obj
            return custom_serializer(model_summary_stats)

    async def reset_usage(self):
        """重置所有用量统计数据"""
        async with self.lock:
            self.usage_data.clear()
            logger.info("Usage statistics have been reset.")

    async def _log_credential_status_summary(self):
        """记录单行凭据状态摘要（仅当状态变化时）"""
        try:
            all_creds = self.credential_manager.get_all_credential_details()
            if not all_creds:
                return

            status_parts = [
                f"{cred.get('email', 'N/A')}({cred.get('status', 'N/A')})" 
                for cred in sorted(all_creds, key=lambda c: c.get('email', ''))
            ]
            
            current_status_str = "; ".join(status_parts)
            if current_status_str != self._last_logged_cred_status_str:
                logger.info(f"Credential Status: {current_status_str}")
                self._last_logged_cred_status_str = current_status_str
        except Exception as e:
            logger.debug(f"Could not log credential status summary: {e}")

    async def _log_usage_summary(self):
        """格式化并输出详细的多级统计日志（仅当数据有变化时）"""
        current_stats_dict = await self.get_usage_snapshot()
        current_stats_str = json.dumps(current_stats_dict, sort_keys=True)

        if not current_stats_dict or current_stats_str == self._last_logged_stats_str:
            logger.debug("Usage stats unchanged, skipping log.")
            return

        logger.debug("Usage stats changed. Generating detailed report.")
        report_lines = ["Credential Usage Stats Report:"]
        
        all_cred_details = {cred['id']: cred for cred in self.credential_manager.get_all_credential_details()}

        # 多级详细报告
        for auth_key in sorted(current_stats_dict.keys()):
            report_lines.append("=" * 60)
            report_lines.append(f"Auth Key: {auth_key}")
            report_lines.append("=" * 60)

            auth_stats = current_stats_dict[auth_key]
            for cred_id in sorted(auth_stats.keys()):
                cred_details = all_cred_details.get(cred_id, {})
                email = cred_details.get("email", "N/A")
                project_id = cred_details.get("project_id", "N/A")
                status = cred_details.get("status", "N/A")
                expiry = cred_details.get("expiry", "N/A")

                report_lines.append("-" * 50)
                report_lines.append(f"  Credential: {cred_id} (email: {email}, project: {project_id}, status: {status}, expiry: {expiry})")

                cred_stats = auth_stats[cred_id]
                for model_name in sorted(cred_stats.keys()):
                    stats_dict = cred_stats[model_name]
                    report_lines.append(f"    - Model: {model_name}")

                    stats = ModelStats(**stats_dict)
                    
                    if stats.successful_requests > 0:
                        report_lines.append(f"      - Successful Requests: {stats.successful_requests}")
                    if stats.total_tokens > 0:
                        report_lines.append(f"      - Total Tokens: {_format_human_readable(stats.total_tokens)}")
                    if stats.prompt_tokens > 0:
                        report_lines.append(f"      - Prompt Tokens: {_format_human_readable(stats.prompt_tokens)}")
                    if stats.candidates_tokens > 0:
                        report_lines.append(f"      - Candidates Tokens: {_format_human_readable(stats.candidates_tokens)}")
                    if stats.thoughts_tokens > 0:
                        report_lines.append(f"      - Thoughts Tokens: {_format_human_readable(stats.thoughts_tokens)}")
                    if stats.cached_content_token_count > 0:
                        report_lines.append(f"      - Cached Content Tokens: {_format_human_readable(stats.cached_content_token_count)}")
                    
                    if stats.failed_requests:
                        report_lines.append("      - Failed Requests:")
                        for reason, count in sorted(stats.failed_requests.items()):
                            report_lines.append(f"        - {reason.title()}: {count}")

        # 按模型全局汇总
        model_summary_stats: Dict[str, ModelStats] = defaultdict(ModelStats)
        for auth_stats in current_stats_dict.values():
            for cred_stats in auth_stats.values():
                for model_name, stats_dict in cred_stats.items():
                    stats = ModelStats(**stats_dict)
                    model_summary_stats[model_name].successful_requests += stats.successful_requests
                    model_summary_stats[model_name].total_tokens += stats.total_tokens
                    model_summary_stats[model_name].prompt_tokens += stats.prompt_tokens
                    model_summary_stats[model_name].candidates_tokens += stats.candidates_tokens
                    model_summary_stats[model_name].thoughts_tokens += stats.thoughts_tokens
                    for reason, count in stats.failed_requests.items():
                        model_summary_stats[model_name].failed_requests[reason] += count

        if model_summary_stats:
            report_lines.append("\n" + "=" * 60)
            report_lines.append("Usage Summary by Model:")
            report_lines.append("=" * 60)
            for model_name in sorted(model_summary_stats.keys()):
                model_stats = model_summary_stats[model_name]
                failed_str = ""
                if model_stats.failed_requests:
                    failed_reasons = ", ".join([
                        f"{reason.title()}: {count}" 
                        for reason, count in sorted(model_stats.failed_requests.items())
                    ])
                    failed_str = f", Failed: [{failed_reasons}]"
                
                report_lines.append(
                    f"  Model: {model_name}, Requests: {model_stats.successful_requests}, "
                    f"Total Tokens: {_format_human_readable(model_stats.total_tokens)}, "
                    f"Prompt: {_format_human_readable(model_stats.prompt_tokens)}, "
                    f"Candidates: {_format_human_readable(model_stats.candidates_tokens)}, "
                    f"Thoughts: {_format_human_readable(model_stats.thoughts_tokens)}{failed_str}"
                )
            report_lines.append("=" * 60)

        logger.info("\n".join(report_lines))
        self._last_logged_stats_str = current_stats_str

    async def _logging_loop(self, interval_sec: int):
        """定期将用量数据和凭据状态打印到日志"""
        while True:
            await asyncio.sleep(interval_sec)
            try:
                await self._log_credential_status_summary()
                await self._log_usage_summary()
            except Exception as e:
                logger.error(f"Error in usage logging loop: {e}", exc_info=True)

    def start_logging_task(self, interval_sec: int):
        """启动后台用量日志记录任务"""
        if self.logging_task and not self.logging_task.done():
            return
        if interval_sec > 0:
            self.logging_task = asyncio.create_task(self._logging_loop(interval_sec))
            logger.info(f"Usage logging task started. Interval: {interval_sec}s")

    def stop_logging_task(self):
        """停止后台用量日志记录任务"""
        if self.logging_task and not self.logging_task.done():
            self.logging_task.cancel()
            logger.info("Usage logging task stopped.")

class PolicyEnforceHook:
    """策略检查 Hook，用于请求准入控制"""
    
    def __init__(self):
        # 未来可以在这里添加配置参数，如速率限制、配额等
        pass

    async def on_request_start(self, ctx: RequestContext):
        """请求开始时进行策略检查"""
        # 当前版本仅作为占位符，直接允许所有请求
        # 未来可在此实现复杂的请求限制逻辑，例如：
        # - 基于 auth_key 的总用量限制
        # - 基于 cred_id 的速率限制
        # - 针对特定模型的访问控制
        # - 黑白名单检查
        # - 时段限制等
        
        # 示例：如果需要拒绝请求，可以抛出异常
        # if some_condition:
        #     raise RequestDeniedError("Request denied by policy", 403)
        
        pass

def create_usage_hooks(credential_manager) -> Tuple[StartHook, EndHook, UsageStatsHook]:
    """创建用量相关的 Hook 实例"""
    usage_stats_hook = UsageStatsHook(credential_manager)
    policy_hook = PolicyEnforceHook()
    
    return policy_hook.on_request_start, usage_stats_hook.on_request_end, usage_stats_hook