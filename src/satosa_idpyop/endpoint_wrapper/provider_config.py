import logging

from idpyoidc.message import Message

from . import get_http_info
from ..core.response import JsonResponse
from ..endpoint_wrapper import EndPointWrapper

logger = logging.getLogger(__name__)

class ProviderConfigEndpointWrapper(EndPointWrapper):
    wraps = ["provider_config"]

    def __call__(self, context, *args, **kwargs):
        _http_info = get_http_info(context)
        _entity_type = self.upstream_get("attribute","entity_type")
        _entity_type.persistence.restore_state(context.request, _http_info)

        logger.debug(f"request: {context.request}")
        logger.debug(f"https_info: {_http_info}")
        parse_req = self.parse_request(context.request, http_info=_http_info)
        logger.debug(f"parse_req: {parse_req}")
        proc_req = self.process_request(context.request, parse_req, _http_info)
        if isinstance(proc_req, JsonResponse):
            self.clean_up()  # pragma: no cover
            return proc_req

        logger.debug(f"Process result: {proc_req}")
        if isinstance(proc_req["response_args"], Message):
            response = JsonResponse(proc_req["response_args"].to_dict())
        else:
            response = JsonResponse(proc_req["response_args"])
        self.clean_up()
        return response
