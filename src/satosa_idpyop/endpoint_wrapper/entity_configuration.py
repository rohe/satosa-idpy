import logging

from . import get_http_info
from ..core.response import JWSResponse
from ..endpoint_wrapper import EndPointWrapper

logger = logging.getLogger(__name__)


class EntityConfigurationEndpointWrapper(EndPointWrapper):
    """
    Construct the Entity Configuration
    served at /.well-known/openid-federation.
    """
    wraps = ["entity_configuration"]

    def __call__(self, context, *args, **kwargs):
        # logger.debug(f"EntityConfiguration: {self.upstream_get('guise')}")

        http_info = get_http_info(context)
        parsed_req = self.parse_request(context.request, http_info=http_info)
        response_args = self.process_request(context, parse_req=parsed_req, http_info=http_info)
        info = self.do_response(response_msg=response_args["response"])

        return JWSResponse(info["response"], content="application/entity-statement+jwt")
