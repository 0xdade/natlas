from ninja import NinjaAPI

from apps.natlas.api import router as natlas_router

api = NinjaAPI(title="Natlas API")
api.add_router("/", natlas_router)
