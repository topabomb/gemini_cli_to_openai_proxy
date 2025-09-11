import random
from typing import List, Optional, Dict, Any
from ..core.types import ManagedCredential, AtomicHealthCheck

class HealthCheckService:
    """
    健康检查策略服务。

    该服务封装了执行健康检查的策略，核心是“随机选择”。
    它持有一系列“原子健康检查”函数，每次被调用时，
    会随机选择一个来执行，以避免行为模式被预测。
    """

    def __init__(self, checkers: Optional[List[AtomicHealthCheck]] = None):
        """
        初始化 HealthCheckService。

        Args:
            checkers: (可选) 一个包含原子健康检查函数的列表。
        """
        self.checkers = checkers or []

    def set_checkers(self, checkers: List[AtomicHealthCheck]):
        """
        设置或更新健康检查函数列表。
        
        Args:
            checkers: 一个包含原子健康检查函数的列表。
        
        Raises:
            ValueError: 如果 checkers 列表为空。
        """
        if not checkers:
            raise ValueError("HealthCheckService requires at least one checker function.")
        self.checkers = checkers

    async def check(self, credential: ManagedCredential) -> Dict[str, Any]:
        """
        对给定的凭据执行一次随机选择的健康检查。

        Args:
            credential: 需要被检查的 ManagedCredential 对象。

        Returns:
            一个包含详细检查结果的字典。
        """
        if not self.checkers:
            return {
                "checker_name": "NoCheckers",
                "is_healthy": True,
                "reason": "No checkers configured."
            }
            
        selected_checker = random.choice(self.checkers)
        is_healthy, reason = await selected_checker(credential)
        
        return {
            "checker_name": selected_checker.__name__,
            "is_healthy": is_healthy,
            "reason": reason
        }
