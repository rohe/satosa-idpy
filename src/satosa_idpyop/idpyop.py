"""
The OpenID4vci (Credential Issuer) frontend module for the satosa proxy
"""
import base64
import logging
import os
from typing import Optional
from urllib.parse import parse_qs
from urllib.parse import urlencode
from urllib.parse import urlparse

import satosa
from fedservice.server import ServerUnit
from idpyoidc.message.oauth2 import AuthorizationErrorResponse
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.server.authn_event import create_authn_event
from satosa.response import SeeOther

from satosa_idpyop.core import ExtendedContext
from satosa_idpyop.core.claims import combine_claim_values
from satosa_idpyop.core.response import JsonResponse
from .endpoint_wrapper import get_http_info
from .endpoints import IdpyOPEndpoints
from .utils import combine_client_subject_id

try:
    from satosa.context import add_prompt_to_context
except ImportError:
    # TODO: remove after https://github.com/IdentityPython/SATOSA/pull/419 is merged
    def add_prompt_to_context(*args, **kwargs):
        pass
from satosa.frontends.base import FrontendModule

from .core.application import idpy_oidc_application as idpy_oidc_app

logger = logging.getLogger(__name__)

IGNORED_HEADERS = ["cookie", "user-agent"]
ALLOW_FEDERATION_RP = True


class IdpyOPFrontend(FrontendModule, IdpyOPEndpoints):
    """
    OpenID Connect frontend module based on idpy-oidc
    """

    def __init__(self,
                 auth_req_callback_func,
                 internal_attributes,
                 conf,
                 base_url,
                 name,
                 endpoint_wrapper_path: Optional[str] = ""
                 ):
        FrontendModule.__init__(self, auth_req_callback_func, internal_attributes, base_url, name)
        self.app = idpy_oidc_app(conf)
        # Static for now
        _servers = [v for k, v in self.app.server.items() if isinstance(v, ServerUnit)]
        # Should only be one
        self.entity_type = _servers[0]
        IdpyOPEndpoints.__init__(self, self.app, auth_req_callback_func, self.converter, endpoint_wrapper_path)
        # registered endpoints will be filled by self.register_endpoints
        self.endpoints = None
        persistence = getattr(self.app.server.federation_entity, "persistence", None)
        if persistence:
            persistence.store_state()

    def register_endpoints(self, backend_names):
        """
        See super class satosa.frontends.base.FrontendModule
        :type backend_names: list[str]
        :rtype: list[(str, ((satosa.context.Context, Any) -> satosa.response.Response, Any))]
        :raise ValueError: if more than one backend is configured
        """
        url_map = []
        for entity_type, item in self.app.server.items():
            if entity_type == "federation_entity":
                for k, v in item.server.endpoint.items():
                    url_map.append((f"^{v.endpoint_path}", getattr(self, f"{k}_endpoint")))
            else:
                for k, v in item.endpoint.items():
                    url_map.append((f"^{v.endpoint_path}", getattr(self, f"{k}_endpoint")))

        # add jwks.json web path
        uri_path = self.app.server["openid_provider"].config["key_conf"]["uri_path"]
        url_map.append((f"^{uri_path}", self.jwks_endpoint))

        logger.debug(f"Loaded OpenID Provider endpoints: {url_map}")
        self.endpoints = url_map
        return url_map

    def handle_error(self,
                     msg: Optional[str] = None,
                     excp: Optional[Exception] = None,
                     status: Optional[str] = "403"
                     ):  # pragma: no cover
        _msg = f'Something went wrong ... {excp or ""}'
        msg = msg or _msg
        logger.error(msg)
        response = JsonResponse(msg, status=status)
        self.clean_up()
        return response

    def clean_up(self):
        _entity_type = self.entity_type
        _entity_type.persistence.flush_session_manager()

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
        logger.debug(f"Internal_resp: {internal_resp}")

        http_info = get_http_info(context)
        logger.debug(f"context.state: {context.state.keys()}")
        orig_req = context.state['authorization']["oidc_request"]

        self.entity_type.persistence.restore_state(orig_req, http_info)
        endpoint = self.entity_type.get_endpoint("authorization")
        _ec = endpoint.upstream_get("context")
        # # have to look up the original authorization request in the PAR db
        # self.entity_type.persistence.restore_pushed_authorization()
        # logger.debug(f"PAR_db: {list(_ec.par_db.keys())}")
        # parse_req = _ec.par_db[orig_req["request_uri"]]
        # client_id = parse_req["client_id"]
        #
        client_id = orig_req["client_id"]
        sub = internal_resp.subject_id
        if not sub:
            sub = internal_resp.attributes["mail"]
        if isinstance(sub, list):
            sub = sub[0]

        authn_event = create_authn_event(
            uid=sub,
            salt=base64.b64encode(os.urandom(self.app.salt_size)).decode(),
            authn_info=internal_resp.auth_info.auth_class_ref,
            # TODO: authn_time=datetime.fromisoformat(
            #  internal_resp.auth_info.timestamp).timestamp(),
        )

        session_manager = _ec.session_manager
        client_info = self.entity_type.persistence.restore_client_info(client_id)
        if not client_info:
            if ALLOW_FEDERATION_RP:
                # This is a third variant besides explicit and automatic.
                # You allow the RP to speak to you because it's a member of the federation
                metadata = self.app.federation_entity.get_verified_metadata(client_id)
                if metadata:
                    client_info = metadata['openid_relying_party']
                    _ec.cdb = {client_id: client_info}

        if not client_info:
            response = JsonResponse(
                {
                    "error": "unauthorized_client",
                    "error_description": "Unknown client"},
                status="403")
            self.clean_up()
            return response

        client_subject_type = client_info.get("subject_type", "public")
        scopes = orig_req.get("scopes", [])
        _session_id = session_manager.create_session(
            authn_event=authn_event,
            auth_req=orig_req,
            user_id=sub,
            client_id=client_id,
            sub_type=client_subject_type,
            scopes=scopes
        )

        try:
            # _args is a dict that contains:
            #  - idpyoidc.message.oidc.AuthorizationResponse
            #  - session_id
            #  - cookie (only need for logout -> not yet supported by Satosa)
            _args = endpoint.authz_part2(
                user=sub,
                session_id=_session_id,
                request=orig_req,
                authn_event=authn_event,
            )
        except ValueError as excp:  # pragma: no cover
            # TODO - cover with unit test and add some satosa logging ...
            return self.handle_error(excp=excp)
        except Exception as excp:  # pragma: no cover
            return self.handle_error(excp=excp)

        logger.debug(f"authz_part2 args: {_args}")

        if isinstance(_args, ResponseMessage) and "error" in _args:
            self.clean_up()  # pragma: no cover
            return JsonResponse(_args, status="403")
        elif isinstance(_args.get("response_args"), AuthorizationErrorResponse):  # pragma: no cover
            rargs = _args.get("response_args")
            logger.error(rargs)
            response = JsonResponse(rargs.to_json(), status="403")
            self.clean_up()
            return response

        kwargs = {
            "fragment_enc": _args.get("fragment_enc", None),
            "return_uri": _args.get("return_uri")
        }

        info = endpoint.do_response(response_args=_args.get("response_args"), request=orig_req,
                                    **kwargs)

        logger.debug(f"Response from OCI: {info}")

        info_response = info["response"]
        _response_placement = info.get(
            "response_placement", endpoint.response_placement
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
            # self._flush_endpoint_context_memory()
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

        # store oidc session with user claims
        client_id = ""
        if context.request:
            client_id = context.request.get("client_id")
        if not client_id:
            oidc_req = context.state["authorization"]["oidc_request"]
            client_id = oidc_req["client_id"]

        _client_subject_id = combine_client_subject_id(client_id, internal_resp.subject_id)
        self.entity_type.persistence.store_claims(combined_claims, _client_subject_id)
        self.entity_type.persistence.store_state(client_id)
        self.clean_up()
        return response
