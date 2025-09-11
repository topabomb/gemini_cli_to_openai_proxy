import random
from typing import List, Optional
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

    async def check(self, credential: ManagedCredential) -> bool:
        """
        对给定的凭据执行一次随机选择的健康检查。

        Args:
            credential: 需要被检查的 ManagedCredential 对象。

        Returns:
            一个布尔值，表示检查是否通过。
        """
        if not self.checkers:
            # 如果没有配置检查器，直接返回 True，相当于跳过检查
            return True
            
        # 从列表中随机选择一个检查函数
        selected_checker = random.choice(self.checkers)
        
        # 执行选定的检查并返回结果
        return await selected_checker(credential)
