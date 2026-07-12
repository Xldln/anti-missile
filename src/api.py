"""API 路由聚合模块 — 被 main.py 通过 `from api import *` 导入。"""

from services.wifi_scout import router as wifi_scout_router

__all__ = ["wifi_scout_router"]
