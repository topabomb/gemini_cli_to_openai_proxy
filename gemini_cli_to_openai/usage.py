"""
用量跟踪与策略执行模块：
- 统计每个凭据、每个模型的成功/失败请求次数和Token消耗。
- 定时输出统计日志，且仅在数据有变化时输出。
- 为未来的请求限制、配额管理等功能提供扩展点。
"""

import json
import logging
import threading
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Dict, Optional, Any, Tuple, DefaultDict, cast

from .credentials import CredentialManager


@dataclass
class ModelStats:
    """每个模型的用量统计"""

    successful_requests: int = 0
    """成功请求的次数"""
    total_tokens: int = 0
    """总 Token 消耗（Prompt + Candidates + Thoughts）"""
    prompt_tokens: int = 0
    """输入（提示词）消耗的 Token 数量"""
    candidates_tokens: int = 0
    """模型生成输出（候选回复）消耗的 Token 数量"""
    thoughts_tokens: int = 0
    """模型内部思考/推理消耗的 Token 数量（Gemini 特有）"""
    cached_content_token_count: int = 0
    """使用缓存内容消耗的 Token 数量"""
    failed_requests: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    """失败请求的统计，按失败原因分类"""


def _format_human_readable(num: int) -> str:
    """将数字转换为人类可读的 k/M 格式。"""
    if num is None:
        return "0"
    if num < 1000:
        return str(num)
    if num < 1_000_000:
        return f"{num / 1000:.2f}k"
    return f"{num / 1_000_000:.2f}M"


def _create_nested_defaultdict():
    """创建可深度复制的嵌套 defaultdict。"""
    return defaultdict(lambda: defaultdict(ModelStats))


StatsDict = DefaultDict[str, DefaultDict[str, DefaultDict[str, ModelStats]]]


class UsageTracker:
    """
    用量跟踪与策略执行中心。
    """

    def __init__(self, credential_manager: CredentialManager):
        """
        初始化 UsageTracker 实例。
        """
        # 数据结构: {auth_key: {cred_id: {model_name: ModelStats}}}
        self.stats: StatsDict = defaultdict(_create_nested_defaultdict)
        self._last_logged_stats: Optional[Dict[str, Any]] = None
        self._last_logged_cred_status: Optional[str] = None
        self.lock = threading.Lock()
        self.credential_manager = credential_manager
        self._log_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def record_successful_request(
        self,
        auth_key: str,
        cred_id: str,
        model_name: str,
        usage_metadata: Dict[str, Any],
    ):
        """线程安全地记录一次成功的 API 调用。"""
        with self.lock:
            stat = self.stats[auth_key][cred_id][model_name]
            stat.successful_requests += 1
            if usage_metadata:
                stat.total_tokens += usage_metadata.get("totalTokenCount", 0)
                stat.prompt_tokens += usage_metadata.get("promptTokenCount", 0)
                stat.candidates_tokens += usage_metadata.get("candidatesTokenCount", 0)
                stat.thoughts_tokens += usage_metadata.get("thoughtsTokenCount", 0)
                stat.cached_content_token_count += usage_metadata.get(
                    "cachedContentTokenCount", 0
                )
        logging.debug(
            f"Recorded successful request for {auth_key}/{cred_id}/{model_name}"
        )

    def record_failed_request(
        self, auth_key: str, cred_id: str, model_name: str, reason: str
    ):
        """线程安全地记录一次失败的 API 调用。"""
        with self.lock:
            stat = self.stats[auth_key][cred_id][model_name]
            stat.failed_requests[reason] += 1
        logging.debug(
            f"Recorded failed request for {auth_key}/{cred_id}/{model_name} due to {reason}"
        )

    def check_request_allowed(
        self, auth_key: str, cred_id: str, model_name: str, base_model_name: str
    ) -> Tuple[bool, str]:
        """
        【架构扩展点】检查一个新请求是否被允许发送。
        """
        # 未来可在此实现复杂的请求限制逻辑
        return True, ""

    def _format_and_log_stats(self):
        """格式化并输出统计日志（仅当数据有变化时）。"""
        with self.lock:
            if not self.stats:
                return

            # 使用 json 序列化来创建可比较的副本，避免 deepcopy 的问题
            # 定义一个辅助函数来处理 dataclass 和 defaultdict
            def custom_serializer(obj):
                if isinstance(obj, (defaultdict, dict)):
                    return {k: custom_serializer(v) for k, v in obj.items()}
                if hasattr(obj, "__dict__"):
                    return custom_serializer(obj.__dict__)
                return obj

            current_stats_dict = custom_serializer(self.stats)

            if current_stats_dict == self._last_logged_stats:
                logging.debug("Usage stats unchanged, skipping log.")
                return

            logging.debug(
                f"Usage stats changed. Current: {current_stats_dict}, Last: {self._last_logged_stats}. Generating report."
            )
            report_lines = ["Credential Usage Stats Report:"]
            sorted_auth_keys = sorted(current_stats_dict.keys())

            for auth_key in sorted_auth_keys:
                report_lines.append("=" * 60)
                report_lines.append(f"Auth Key: {auth_key}")
                report_lines.append("=" * 60)

                auth_stats = current_stats_dict[auth_key]
                sorted_cred_ids = sorted(auth_stats.keys())

                for cred_id in sorted_cred_ids:
                    cred_details = self.credential_manager.get_credential_details(
                        cred_id
                    )
                    email = cred_details.get("email", "N/A")
                    project_id = cred_details.get("project_id", "N/A")
                    status = cred_details.get("status", "N/A")
                    expiry = cred_details.get("expiry", "N/A")

                    report_lines.append("-" * 50)
                    report_lines.append(
                        f"  Credential: {cred_id} (email: {email}, project: {project_id}, status: {status}, expiry: {expiry})"
                    )

                    cred_stats = auth_stats[cred_id]
                    sorted_models = sorted(cred_stats.keys())

                    for model_name in sorted_models:
                        stats_dict = cred_stats[model_name]
                        report_lines.append(f"    - Model: {model_name}")

                        for key, value in sorted(stats_dict.items()):
                            if key == "failed_requests":
                                if value:
                                    report_lines.append(
                                        f"      - {key.replace('_', ' ').title()}:"
                                    )
                                    for reason, count in sorted(value.items()):
                                        report_lines.append(
                                            f"        - {reason.title()}: {count}"
                                        )
                            elif isinstance(value, int) and value > 0:
                                formatted_value = (
                                    _format_human_readable(value)
                                    if "token" in key.lower()
                                    else str(value)
                                )
                                report_lines.append(
                                    f"      - {key.replace('_', ' ').title()}: {formatted_value}"
                                )

            # 按模型汇总用量
            model_summary_stats: DefaultDict[str, ModelStats] = defaultdict(ModelStats)
            for auth_stats in current_stats_dict.values():
                for cred_stats in auth_stats.values():
                    for model_name, stats_dict in cred_stats.items():
                        model_summary_stats[model_name].successful_requests += stats_dict.get("successful_requests", 0)
                        model_summary_stats[model_name].total_tokens += stats_dict.get("total_tokens", 0)
                        model_summary_stats[model_name].prompt_tokens += stats_dict.get("prompt_tokens", 0)
                        model_summary_stats[model_name].candidates_tokens += stats_dict.get("candidates_tokens", 0)
                        model_summary_stats[model_name].thoughts_tokens += stats_dict.get("thoughts_tokens", 0)
                        for reason, count in stats_dict.get("failed_requests", {}).items():
                            model_summary_stats[model_name].failed_requests[reason] += count

            if model_summary_stats:
                report_lines.append("\n" + "=" * 60)
                report_lines.append("Usage Summary by Model:")
                report_lines.append("=" * 60)
                for model_name in sorted(model_summary_stats.keys()):
                    model_stats = model_summary_stats[model_name]
                    failed_str = ""
                    if model_stats.failed_requests:
                        failed_reasons = ", ".join([f"{reason.title()}: {count}" for reason, count in sorted(model_stats.failed_requests.items())])
                        failed_str = f", Failed: [{failed_reasons}]"
                    report_lines.append(
                        f"  Model: {model_name}, Requests: {model_stats.successful_requests}, "
                        f"Total Tokens: {_format_human_readable(model_stats.total_tokens)}, "
                        f"Prompt: {_format_human_readable(model_stats.prompt_tokens)}, "
                        f"Candidates: {_format_human_readable(model_stats.candidates_tokens)}, "
                        f"Thoughts: {_format_human_readable(model_stats.thoughts_tokens)}{failed_str}"
                    )
                report_lines.append("=" * 60)

            logging.info("\n".join(report_lines))

            self._last_logged_stats = current_stats_dict

    def _log_credential_status_summary(self):
        """记录单行凭据状态摘要（仅当状态变化时）。"""
        try:
            with self.lock:
                all_creds = self.credential_manager.credentials
                if not all_creds:
                    return

                status_parts = []
                for cred in sorted(all_creds, key=lambda c: c.email or ""):
                    email = cred.email or "unknown"
                    status = cred.status
                    status_parts.append(f"{email}({status})")
                
                current_status_str = "; ".join(status_parts)
                if current_status_str != self._last_logged_cred_status:
                    logging.info(f"Credential Status: {current_status_str}")
                    self._last_logged_cred_status = current_status_str
        except Exception as e:
            logging.debug(f"Could not log credential status summary: {e}")

    def _logging_loop(self, interval_sec: int):
        """后台日志循环。"""
        logging.debug(f"Usage logging loop started.")
        while not self._stop_event.wait(interval_sec):
            try:
                # 1. 定期输出凭据状态摘要
                self._log_credential_status_summary()
                # 2. 按需输出详细用量报告
                logging.debug("Executing periodic usage stats check.")
                self._format_and_log_stats()
            except Exception as e:
                logging.error(f"Error in usage stats logging loop: {e}")
        logging.debug("Usage logging loop stopped.")

    def start_logging_task(self, interval_sec: int = 30):
        """启动后台日志线程。"""
        if self._log_thread and self._log_thread.is_alive():
            return
        self._stop_event.clear()
        self._log_thread = threading.Thread(
            target=self._logging_loop, args=(interval_sec,), daemon=True
        )
        self._log_thread.start()
        logging.debug(f"Usage stats logging task started with {interval_sec}s interval.")

    def stop_logging_task(self):
        """停止后台日志线程。"""
        if self._log_thread:
            self._stop_event.set()
            self._log_thread.join(timeout=5)
            logging.info("Usage stats logging task stopped.")
