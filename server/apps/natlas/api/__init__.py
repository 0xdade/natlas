from ninja import Router

from apps.natlas.api.agents import router as agents_router
from apps.natlas.api.scope import router as scope_router
from apps.natlas.api.status import router as status_router
from apps.natlas.api.tags import router as tags_router

router = Router()
router.add_router("/agents", agents_router)
router.add_router("/scope", scope_router)
router.add_router("/tags", tags_router)
router.add_router("", status_router)
