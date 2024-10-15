import logging

from openid4v.message import auth_detail_list_deser
from openid4v.message import AuthorizationDetail

from . import EndPointWrapper
from ..utils import get_http_info
from ..core import ExtendedContext
from ..core.response import JsonResponse

logger = logging.getLogger(__name__)


class PushedAuthorizationEndpointWrapper(EndPointWrapper):
    wraps = ["pushed_authorization"]

    def __call__(self, context: ExtendedContext):
        _entity_type = self.upstream_get("attribute", "entity_type")
        _http_info = get_http_info(context)
        _entity_type.persistence.restore_state(context.request, _http_info)
        self.load_cdb(context)

        logger.debug(f"Incoming request: {context.request}")
        self.pre_parse_request(context)
        logger.debug(f"Done pre_parse_request")
        parse_req = self.parse_request(context.request, http_info=_http_info)
        logger.debug(f"Done parse_request: {parse_req}")
        parse_req = self.post_parse_request(context=context, parse_req=parse_req)
        logger.debug(f"Done post_parse_request: {parse_req}")

        proc_resp = self.process_request(context, parse_req, _http_info)
        if isinstance(proc_resp, JsonResponse):
            self.clean_up()  # pragma: no cover
            return proc_resp

        # The only thing that should have changed on the application side
        _entity_type.persistence.store_client_info(parse_req["client_id"])
        _entity_type.persistence.store_pushed_authorization()
        # Also on the federation side
        _fed_entity = self.upstream_get("federation_entity")
        _fed_entity.persistence.store_state()

        logger.debug(f"PAR response: {proc_resp}")
        response = JsonResponse(proc_resp["http_response"])
        self.clean_up()
        return response

    def pre_parse_request(self, context: ExtendedContext):
        return

    def post_parse_request(self, context: ExtendedContext, parse_req):
        return parse_req


class PushedAuthorizationEndpointWrapperAuthorizationDetail(EndPointWrapper):

    def pre_parse_request(self, context: ExtendedContext):
        # This is not how it should be done, but it has to be done.
        logger.debug(f"Before adl: {context.request['authorization_details']}")
        adl = auth_detail_list_deser(context.request["authorization_details"], sformat="urlencoded")
        logger.debug(f"adl: {adl} {type(adl)}")
        context.request["authorization_details"] = [v.to_dict() for v in adl]

    def post_parse_request(self, context: ExtendedContext, parse_req):
        logger.debug(f"Parsed request: {parse_req} {type(parse_req)}")
        logger.debug(f"ad type: {type(context.request['authorization_details'][0])}")
        logger.debug(f"cd type: {type(context.request['authorization_details'][0]['credential_definition'])}")
        parse_req["authorization_details"] = [AuthorizationDetail(**item) for item in
                                              parse_req["authorization_details"]]
        return parse_req
