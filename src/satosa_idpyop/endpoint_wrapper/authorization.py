import base64
import logging
import os
from urllib.parse import parse_qs
from urllib.parse import urlencode
from urllib.parse import urlparse

from idpyoidc.message.oauth2 import AuthorizationErrorResponse
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.server.authn_event import create_authn_event
from openid4v.message import AuthorizationDetail
from openid4v.message import AuthorizationRequest
import satosa

from . import EndPointWrapper
from ..core import ExtendedContext
from ..core.claims import combine_claim_values
from ..core.response import JsonResponse
from ..utils import get_http_info

logger = logging.getLogger(__name__)

try:
    from satosa.context import add_prompt_to_context
except ImportError:
    # TODO: remove after https://github.com/IdentityPython/SATOSA/pull/419 is merged
    def add_prompt_to_context(*args, **kwargs):
        pass
from satosa.internal import InternalData
import satosa.logging_util as lu
from satosa.response import SeeOther

logger = logging.getLogger(__name__)


def handle_authorization_details_decoding(request):
    if request["authorization_details"].startswith("[") and request[
        "authorization_details"].endswith("]"):
        _ads = request["authorization_details"][1:-1].split(",")
        _list = []
        for _url_ad in _ads:
            _url_ad = _url_ad[1:-1]
            _item = AuthorizationDetail().from_urlencoded(_url_ad)
            _list.append(_item.to_dict())
        request["authorization_details"] = _list
    return request


class AuthorizationEndpointWrapper(EndPointWrapper):
    wraps = ['authorization']

    def __init__(self, upstream_get, endpoint, auth_req_callback_func, converter,
                 **kwargs):  # pragma: no cover
        EndPointWrapper.__init__(self, upstream_get=upstream_get, endpoint=endpoint, **kwargs)
        self.auth_req_callback_func = auth_req_callback_func
        self.converter = converter
        self.entity_type = self.upstream_get("guise")

    def __call__(self, context: ExtendedContext):
        """
        OAuth2 / OIDC Authorization endpoint
        Checks client_id and handles the authorization request
        """
        self.log_request(context, "Authorization endpoint request")
        self.load_cdb(context)

        internal_req = self.handle_authn_request(context)
        if not isinstance(internal_req, InternalData):
            self.clean_up()
            return internal_req

        return self.auth_req_callback_func(context, internal_req)

    def _handle_authn_request(self, context: ExtendedContext):
        """
        Parse and verify the authentication request into an internal request.
        :type context: satosa.context.Context
        :rtype: satosa.internal.InternalData

        :param context: the current context
        :return: the internal request
        """
        self.log_request(context, "OAuth2 Authorization request from client")
        logger.debug(f"{self.endpoint.name}")
        logger.debug(f"request at frontend: {context.request}")

        # FIX
        if "authorization_details" in context.request:
            handle_authorization_details_decoding(context.request)

        http_info = get_http_info(context)
        parse_req = self.parse_request(context.request, http_info=http_info)
        if isinstance(parse_req, AuthorizationErrorResponse):
            logger.debug(f"{context.request}, {parse_req._dict}")
            self.clean_up()
            return JsonResponse(parse_req._dict)

        client_id = parse_req.get("client_id")

        _entity_type = self.upstream_get("attribute", "entity_type")
        _entity_type.persistence.restore_state(parse_req, http_info)
        # _entity_type.persistence.load_claims(client_id)

        context.state[self.endpoint.name] = {"oidc_request": context.request}

        _client_conf = self.endpoint.upstream_get("context").cdb[client_id]
        client_name = _client_conf.get("client_name")
        subject_type = _client_conf.get("subject_type", "pairwise")
        if client_name:
            requester_name = [{"lang": "en", "text": client_name}]
        else:  # pragma: no cover
            requester_name = None

        internal_req = InternalData(
            subject_type=subject_type,
            requester=client_id,
            requester_name=requester_name,
        )

        _claims_supported = self.endpoint.upstream_get("context").get_preference("claims_supported")

        logger.debug(f"Claims supported: {_claims_supported}")

        if _claims_supported:
            internal_req.attributes = self.converter.to_internal_filter("openid", _claims_supported)

        context.target_backend = self.upstream_get("attribute", "app").default_target_backend
        context.internal_data = internal_req
        return internal_req

    def handle_authn_request(self, context: ExtendedContext):
        """
        Handle an authentication request and pass it on to the backend.
        :type context: satosa.context.Context
        :rtype: satosa.response.SeeOther

        :param context: the current context
        :return: HTTP response to the client
        """
        internal_req = self._handle_authn_request(context)
        if not isinstance(internal_req, InternalData):
            self.clean_up()
            return internal_req
        return self.auth_req_callback_func(context, internal_req)

    def _handle_backend_response(self, context: ExtendedContext, internal_resp):
        """
        Called by handle_authn_response, once a backend made its work
        :type context: satosa.context.Context
        :rtype: satosa.response.Response

        :param context: the current context
        :param internal_resp: satosa internal data
        :type internal_resp: satosa.internal.InternalData
        :return: HTTP response to the client
        """
        http_info = get_http_info(context)
        oidc_req = context.state[self.endpoint.name]["oidc_request"]
        self.entity_type.persistence.restore_client_info(oidc_req["client_id"])

        # not using self._parse_request cause of "Missing required attribute 'response_type'"
        parse_req = AuthorizationRequest().from_urlencoded(urlencode(oidc_req))

        proc_req = self.process_request(context, parse_req, http_info)

        if isinstance(proc_req, JsonResponse):
            self.clean_up()  # pragma: no cover
            return proc_req

        client_id = parse_req["client_id"]
        sub = internal_resp.subject_id

        authn_event = create_authn_event(
            uid=sub,
            salt=base64.b64encode(
                os.urandom(self.upstream_get("attribute", "app").salt_size)).decode(),
            authn_info=internal_resp.auth_info.auth_class_ref,
            # TODO: authn_time=datetime.fromisoformat(
            #  internal_resp.auth_info.timestamp).timestamp(),
        )

        _ec = self.endpoint.upstream_get("context")
        _token_usage_rules = _ec.authn_broker.get_method_by_id("user")

        session_manager = _ec.session_manager
        client = self.upstream_get("attribute", "app").storage.get_client_by_id(client_id)
        client_subject_type = client.get("subject_type", "public")
        _session_id = session_manager.create_session(
            authn_event=authn_event,
            auth_req=parse_req,
            user_id=sub,
            client_id=client_id,
            sub_type=client_subject_type,
            token_usage_rules=_token_usage_rules,
        )

        try:
            # _args is a dict that contains:
            #  - idpyoidc.message.oidc.AuthorizationResponse
            #  - session_id
            #  - cookie (only need for logout -> not yet supported by Satosa)
            _args = self.endpoint.authz_part2(
                user=sub,
                session_id=_session_id,
                request=parse_req,
                authn_event=authn_event,
            )
        except ValueError as excp:  # pragma: no cover
            # TODO - cover with unit test and add some satosa logging ...
            return self.handle_error(excp=excp)
        except Exception as excp:  # pragma: no cover
            return self.handle_error(excp=excp)

        if isinstance(_args, ResponseMessage) and "error" in _args:
            self.clean_up()
            return JsonResponse(_args, status="403")
        elif isinstance(
                _args.get("response_args"), AuthorizationErrorResponse
        ):  # pragma: no cover
            rargs = _args.get("response_args")
            logger.error(rargs)
            response = JsonResponse(rargs.to_json(), status="403")
            self.clean_up()
            return response

        info = self.endpoint.do_response(request=parse_req, **proc_req)
        info_response = info["response"]
        _response_placement = info.get(
            "response_placement", self.endpoint.response_placement
        )
        if _response_placement == "url":
            data = _args["response_args"].to_dict()
            url_components = urlparse(info_response)
            original_params = parse_qs(url_components.query)
            merged_params = {**original_params, **data}
            updated_query = urlencode(merged_params, doseq=True)
            redirect_url = url_components._replace(query=updated_query).geturl()
            logger.debug(f"Redirect to: {redirect_url}")
            resp = SeeOther(redirect_url)
        else:  # pragma: no cover
            self.entity_type.persistence.flush_session_manager()
            raise NotImplementedError()

        # I don't flush in-mem db because it will be flushed by handle_authn_response
        return resp

    def handle_authn_response(self, context: ExtendedContext, internal_resp):
        """
        See super class method satosa.frontends.base.FrontendModule#handle_authn_response
        :type context: satosa.context.Context
        :type internal_resp: satosa.internal.InternalData
        :rtype satosa.response.SeeOther
        """
        _claims = self.converter.from_internal("openid", internal_resp.attributes)
        claims = {k: v for k, v in _claims.items() if v}
        combined_claims = dict([i for i in combine_claim_values(claims.items())])

        response = self._handle_backend_response(context, internal_resp)
        # TODO - why should we have to delete it?
        # del context.state[self.name]

        # store oidc session with user claims
        self.entity_type.persistence.store_state(claims=combined_claims)
        self.clean_up()
        return response

    def handle_backend_error(self, exception: Exception):
        """
        See super class satosa.frontends.base.FrontendModule
        :type exception: satosa.exception.SATOSAError
        :rtype: oic.utils.http_util.Response
        """
        auth_req = AuthorizationRequest().from_urlencoded(
            urlencode(exception.state[self.endpoint.name]["oidc_request"])
        )
        msg = exception.message
        error_resp = AuthorizationErrorResponse(
            error="access_denied",
            error_description=msg,
            # If the client sent us a state parameter, we should reflect it back according to the
            # spec
            **({"state": auth_req["state"]} if "state" in auth_req else {}),
        )
        logline = lu.LOG_FMT.format(
            id=lu.get_session_id(exception.state), message=msg)
        logger.info(logline)
        return SeeOther(
            error_resp.request(
                auth_req["redirect_uri"], auth_req["response_type"] != ["code"]
            )
        )
