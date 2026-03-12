from ninja import Router

from apps.natlas.web.dashboard import router as dashboard_router
from apps.natlas.web.hosts import router as hosts_router

router = Router()
router.add_router("", dashboard_router)
router.add_router("", hosts_router)
