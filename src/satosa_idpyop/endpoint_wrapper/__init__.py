import importlib
import inspect
import logging
import os
from os.path import isfile
from os.path import join
from typing import Optional

from cryptojwt import KeyJar
from fedservice.entity import get_verified_trust_chains
from idpyoidc.message import Message
from idpyoidc.message.oidc import AuthnToken
from idpyoidc.server import Endpoint
from idpyoidc.server.exception import ClientAuthenticationError
from idpyoidc.server.exception import InvalidClient
from idpyoidc.server.exception import UnAuthorizedClient
from idpyoidc.server.exception import UnknownClient
from satosa.context import Context
from satosa_idpyop.utils import IGNORED_HEADERS

from ..core import ExtendedContext

try:
    from satosa.context import add_prompt_to_context
except ImportError:
    def add_prompt_to_context(*args, **kwargs):
        pass
import satosa.logging_util as lu

from ..core.response import JsonResponse

logger = logging.getLogger(__name__)

IGNORED_HEADERS = ["cookie", "user-agent"]
BASEDIR = os.path.abspath(os.path.dirname(__file__))


def get_http_info(context: ExtendedContext):
    """
    Aligns parameters for idpy_oidc interoperability needs
    """
    http_info = {"headers": {}}

    if getattr(context, "http_info", None):
        http_info = {
            "headers": {
                k.lower(): v
                for k, v in context.http_info.items()
                if k not in IGNORED_HEADERS
            },
            "method": context.request_method,
            "url": context.request_uri,
        }

    if getattr(context, "request_authorization", None):
        http_info["headers"].update(
            {"authorization": context.request_authorization}
        )

    context.http_info = http_info

    return http_info


class EndPointWrapper(object):
    wraps = []

    def __init__(self, upstream_get, endpoint, **kwargs):
        self.upstream_get = upstream_get
        self.endpoint = endpoint
        self.kwargs = kwargs

    def __call__(self, *args, **kwargs):
        pass

    def parse_request(self, request: dict, http_info: dict):
        """
        Returns a parsed OAuth2/OIDC request, used by endpoints views
        """
        try:
            parse_req = self.endpoint.parse_request(request, http_info=http_info)
        except (
                InvalidClient,
                UnknownClient,
                UnAuthorizedClient,
                ClientAuthenticationError,
        ) as err:
            logger.error(err)
            response = JsonResponse(
                {"error": "unauthorized_client", "error_description": str(err)},
                status="403",
            )
            self.clean_up()
            return response
        return parse_req

    def process_request(self, context: Context, parse_req, http_info):
        """
        Processes an OAuth2/OIDC request, used by endpoint views
        """
        if isinstance(parse_req, JsonResponse):
            self.clean_up()
            return parse_req

        # # do not let idpy-oidc handle prompt, handle it here instead
        # prompt_arg = parse_req.pop("prompt", None)
        # if prompt_arg:
        #     add_prompt_to_context(
        #         context, " ".join(prompt_arg) if isinstance(prompt_arg, list) else prompt_arg)
        #
        # # save ACRs
        # acr_values = parse_req.pop("acr_values", None)
        # if acr_values:
        #     acr_values = acr_values if isinstance(acr_values, list) else acr_values.split(" ")
        #     context.decorate(Context.KEY_AUTHN_CONTEXT_CLASS_REF, acr_values)
        #     context.state[Context.KEY_AUTHN_CONTEXT_CLASS_REF] = acr_values

        try:
            proc_req = self.endpoint.process_request(parse_req, http_info=http_info)
            return proc_req
        except Exception as err:  # pragma: no cover
            logger.error(
                f"In {self.endpoint.name}.process_request: {parse_req.__dict__} - {err}")
            response = JsonResponse(
                {
                    "error": "invalid_request",
                    "error_description": "request cannot be processed",
                },
                status="403",
            )
            self.clean_up()
            return response

    def do_response(self, response_args: Optional[dict] = None, request: Optional[dict] = None, **kwargs):
        try:
            return self.endpoint.do_response(response_args=response_args, request=request, **kwargs)
        except Exception as err:  # pragma: no cover
            logger.error(
                f"In {self.endpoint.name}.do_response: {response_args.__dict__} - {err}")
            response = JsonResponse(
                {
                    "error": "invalid_request",
                    "error_description": "response cannot be created",
                },
                status="403",
            )
            self.clean_up()
            return response

    def log_request(self, context: ExtendedContext, msg: str, level: Optional[str] = "info"):
        _msg = f"{msg}: {context.request}"
        logline = lu.LOG_FMT.format(
            id=lu.get_session_id(context.state), message=_msg)
        getattr(logger, level)(logline)

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
        _entity_type = self.upstream_get("attribute", "entity_type")
        _entity_type.persistence.flush_session_manager()

    def load_cdb(self, context: ExtendedContext, client_id: Optional[str] = None) -> dict:
        """
        gets client_id from local storage and updates the client DB
        """
        if client_id:
            client_id = client_id
        elif context.request and isinstance(context.request, (dict, Message)):
            client_id = context.request.get("client_id")

        _entity_type = self.upstream_get("attribute", "entity_type")
        _ec = _entity_type.context
        _persistence = _entity_type.persistence

        if client_id:
            client_info = _persistence.restore_client_info(client_id)
        elif "Basic " in getattr(context, "request_authorization", ""):
            # here even for introspection endpoint
            client_info = _persistence.restore_client_info_by_basic_auth(
                context.request_authorization) or {}
            client_id = client_info.get("client_id")
        elif context.request and context.request.get(
                "client_assertion"
        ):  # pragma: no cover
            # this is not a validation just a client detection
            # validation is demanded later by idpy_oidc parse_request

            ####
            # WARNING: private_key_jwt can't be supported in SATOSA directly to token endpoint
            # because the user MUST always pass through the authorization endpoint
            ####
            token = AuthnToken().from_jwt(
                txt=context.request["client_assertion"],
                keyjar=KeyJar(),  # keyless keyjar
                verify=False,  # otherwise keyjar MUST contain the issuer key
            )
            client_id = token.get("iss")
            client_info = _persistence.restore_client_info(client_id)

        elif "Bearer " in getattr(context, "request_authorization", ""):
            client_info = _persistence.restore_client_info_by_bearer_token(
                context.request_authorization) or {}
            client_id = client_info.get("client_id")

        else:  # pragma: no cover
            _ec.cdb = {}
            _msg = f"Client {client_id} not found!"
            logger.warning(_msg)
            raise InvalidClient(_msg)

        if client_info:
            logger.debug(
                f"Loaded oidcop client: {client_info}")
        else:  # pragma: no cover
            logger.info(f'Cannot find "{client_id}" in client DB')
            _federation_entity = self.upstream_get("federation_entity")
            trust_chains = get_verified_trust_chains(_federation_entity, client_id)
            if trust_chains:
                _federation_entity.store_trust_chains(client_id, trust_chains)
                client_info = trust_chains[0].metadata["openid_relying_party"]
                _ec.cdb = {client_id: client_info}
            else:
                raise UnknownClient(client_id)

        _jwks_uri = client_info.get("jwks_uri", None)
        if _jwks_uri:
            _ec.keyjar.load_keys(client_id, jwks_uri=_jwks_uri)
        else:
            _jwks = client_info.get("jwks", None)
            if _jwks:
                _ec.keyjar.import_jwks(_jwks, client_id)

        # BUT specs are against!
        # https://openid.net/specs/openid-connect-registration-1_0.html#ReadRequest
        _rat = client_info.get("registration_access_token")
        if _rat:
            _ec.registration_access_token[_rat] = client_info["client_id"]
        else:
            _ec.registration_access_token = {}
        return client_info


def get_endpoint_wrapper(endpoint: Endpoint):
    path = "satosa_idpyop.endpoint_wrapper"
    files = [f for f in os.listdir(BASEDIR) if isfile(join(BASEDIR, f)) and f.endswith('.py')]
    for f in files:
        f = f[:-3]
        module = importlib.import_module(f"{path}.{f}")
        clsmembers = inspect.getmembers(module, inspect.isclass)
        for name, cls in clsmembers:
            if name.endswith("EndpointWrapper"):
                if endpoint.name in cls.wraps:
                    return cls
    return None
