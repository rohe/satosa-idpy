from idpyoidc.message.oauth2 import TokenErrorResponse
from idpyoidc.message.oidc import AccessTokenRequest
from idpyoidc.server.exception import NoSuchGrant
from idpyoidc.server.exception import UnknownClient

from . import get_http_info
from ..core.response import JsonResponse
from ..endpoint_wrapper import EndPointWrapper


class TokenEndpointWrapper(EndPointWrapper):
    """
    Handle token requests (served at /token).
    """
    wraps = ["token"]

    def __call__(self, context, *args, **kwargs):
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

        _entity_type = self.upstream_get("attribute", "entity_type")
        # in token endpoint we cannot parse a request without having loaded cdb and session first
        try:
            _entity_type.persistence.restore_state(raw_request, _http_info)
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

        if isinstance(proc_req["response_args"].get("scope", str), list):
            proc_req["response_args"]["scope"] = " ".join(proc_req["response_args"]["scope"])

        # should only be one client in the client db
        _client_id = list(_entity_type.context.cdb.keys())[0]
        _entity_type.persistence.store_state(_client_id)

        # better return jwt or jwe here!
        response = JsonResponse(proc_req["response_args"])
        self.clean_up()
        return response
