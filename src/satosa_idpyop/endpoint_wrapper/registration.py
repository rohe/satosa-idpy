import logging

from cryptojwt.jws.jws import factory

from ..core.response import JWSResponse
from ..endpoint_wrapper import EndPointWrapper
from ..utils import get_http_info

logger = logging.getLogger(__name__)


class RegistrationEndpointWrapper(EndPointWrapper):
    """
    Construct the Entity Configuration
    served at /.well-known/openid-federation.
    """
    wraps = ["registration"]

    def __call__(self, context, *args, **kwargs):
        # logger.debug(f"Registration: {self.upstream_get('guise')}")
        logger.debug(20 * "*" + f" registration wrapper endpoint " + 20 * "=")
        http_info = get_http_info(context)
        parsed_req = self.parse_request(context.request, http_info=http_info)
        logger.debug(f"parsed request: {parsed_req}")
        response_args = self.process_request(context, parse_req=parsed_req, http_info=http_info)
        logger.debug(f"Registration response args: {response_args}")
        info = self.do_response(response_msg=response_args["response_msg"])
        logger.debug(f"Registration response info: {info}")

        _jws = factory(info["response"])
        logger.debug(f"Payload: {_jws.jwt.payload()}")
        _client_id = _jws.jwt.payload()["sub"]
        logger.debug(f"Client ID: {_client_id}")
        _guise = self.get_guise()
        _guise.persistence.store_client_info(_client_id)

        return JWSResponse(info["response"], content="application/entity-statement+jwt")
