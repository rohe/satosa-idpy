import logging

from idpyoidc.message.oauth2 import TokenErrorResponse
from idpyoidc.message.oidc import AccessTokenRequest
from idpyoidc.server.exception import NoSuchGrant
from idpyoidc.server.exception import UnknownClient
from openid4v import ServerEntity

from ..core.response import JsonResponse
from ..endpoint_wrapper import EndPointWrapper
from ..utils import get_http_info

logger = logging.getLogger(__name__)


class TokenEndpointWrapper(EndPointWrapper):
    """
    Handle token requests (served at /token).
    """
    wraps = ["token"]

    def __call__(self, context, *args, **kwargs):
        logger.debug(20 * "=" + f"TokenEndpointWrapper")
        _http_info = get_http_info(context)

        try:
            self.load_cdb(context)
        except UnknownClient:
            self.clean_up()
            return JsonResponse(
                {
                    "error": "unauthorized_client",
                    "error_description": "unknown client",
                }
            )

        raw_request = AccessTokenRequest(**context.request)

        _unit = self.upstream_get("unit")
        if isinstance(_unit, ServerEntity):
            logger.debug("ServerEntity")
            _guise = _unit
        else:
            if self.endpoint.endpoint_type == "oidc":
                _guise = _unit.pick_guise('openid_provider')
            else:
                _guise = _unit.pick_guise('oauth_authority_server')

            if not _guise:
                logger.error(f"Could not find quise")
                logger.info(f"Endpoint type: {self.endpoint.endpoint_type}")
                logger.info(f"Unit: {_unit}")

        # in token endpoint we cannot parse a request without having loaded cdb and session first
        try:
            _guise.persistence.restore_state(raw_request, _http_info)
        except NoSuchGrant:
            _response = JsonResponse(
                {
                    "error": "invalid_request",
                    "error_description": "Not owner of token",
                },
                status="403",
            )
            self.clean_up()
            return _response

        parse_req = self.parse_request(context.request, http_info=_http_info)
        proc_req = self.process_request(context, parse_req, _http_info)

        if isinstance(proc_req, JsonResponse):
            self.clean_up()  # pragma: no cover
            return proc_req
        elif isinstance(proc_req, TokenErrorResponse):
            self.clean_up()
            return JsonResponse(proc_req.to_dict(), status="403")

        _scopes = proc_req["response_args"].get("scope", None)
        if _scopes:
            if isinstance(_scopes, list):
                proc_req["response_args"]["scope"] = " ".join(_scopes)
            elif isinstance(_scopes, str):
                proc_req["response_args"]["scope"] = _scopes
        elif _scopes is not None:
            del proc_req["response_args"]["scope"]

        # should only be one client in the client db
        _client_id = list(_guise.context.cdb.keys())[0]
        _guise.persistence.store_state(_client_id)

        # better return jwt or jwe here!
        response = JsonResponse(proc_req["response_args"])
        self.clean_up()
        return response
