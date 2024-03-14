import logging

from ..core.response import JsonResponse
from ..endpoint_wrapper import EndPointWrapper

logger = logging.getLogger(__name__)


class JWKSEndpointWrapper(EndPointWrapper):
    """
    Construct the JWKS document (served at /jwks).
    """

    def __call__(self, *args, **kwargs):
        logger.debug("At the JWKS endpoint")
        jwks = self.upstream_get("attribute", "entity_type").context.keyjar.export_jwks("")
        return JsonResponse(jwks)
