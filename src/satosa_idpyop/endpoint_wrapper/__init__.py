import importlib
import inspect
import logging
import os
from os.path import isfile
from os.path import join
from typing import Optional
from urllib.parse import urlparse

from cryptojwt import KeyJar
from cryptojwt.jws.jws import factory
from fedservice.entity import get_verified_trust_chains
from idpyoidc.key_import import import_jwks
from idpyoidc.message import Message
from idpyoidc.message.oidc import AuthnToken
from idpyoidc.server import Endpoint
from idpyoidc.server.exception import ClientAuthenticationError
from idpyoidc.server.exception import InvalidClient
from idpyoidc.server.exception import UnAuthorizedClient
from idpyoidc.server.exception import UnknownClient
from openid4v import ServerEntity
from satosa.context import Context

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


class EndPointWrapper(object):
    wraps = []

    def __init__(self, upstream_get, endpoint, **kwargs):
        self.upstream_get = upstream_get
        self.endpoint = endpoint
        self.kwargs = kwargs

    def __call__(self, *args, **kwargs):
        pass

    def get_guise(self):
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
        return _guise

    def parse_request(self, request: dict, http_info: dict):
        """
        Returns a parsed OAuth2/OIDC request, used by endpoints views
        """
        try:
            logger.debug(f">>> {self.endpoint.name}.parse_request: {request}")
            if self.endpoint.name == "credential":
                _guise = self.get_guise()
                _guise.persistence.restore_state(request, http_info)
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
        except Exception as err:
            logger.exception(f"Unexpected exception in parse_request")
            response = JsonResponse(
                {"error": "Parsing error", "error_description": str(err)},
                status="403",
            )
            self.clean_up()
            return response

        return parse_req

    def process_request(self, context: Context, parse_req, http_info, **kwargs):
        """
        Processes an OAuth2/OIDC request
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

        logger.info(20 * "=" + f" {self.endpoint.name}.process_request: {parse_req}")

        if self.endpoint.name == "credential":
            _frontend = self.upstream_get("unit")
            _srv = _frontend.pick_guise('openid_provider')
            if not _srv:
                _srv = _frontend.pick_guise('oauth_authorization_server')
            # Use that to get the appropriate persistence layer
            _persistence = _srv.persistence
            logger.debug("Restore state")
            _persistence.restore_state(parse_req, http_info)

        try:
            proc_req = self.endpoint.process_request(parse_req, http_info=http_info, **kwargs)
            return proc_req
        except Exception as err:  # pragma: no cover
            logger.exception("process_request")
            response = JsonResponse(
                {
                    "error": "invalid_request",
                    "error_description": f"request cannot be processed {err}",
                },
                status="403",
            )
            self.clean_up()
            return response

    def do_response(self, response_args: Optional[dict] = None, request: Optional[dict] = None,
                    **kwargs):
        logger.info(f"In {self.endpoint.name}.do_response")
        try:
            return self.endpoint.do_response(response_args=response_args, request=request, **kwargs)
        except Exception as err:  # pragma: no cover
            logger.error(f"{err}")
            response = JsonResponse(
                {
                    "error": "invalid_request",
                    "error_description": f"response cannot be created : {err}",
                },
                status="403",
            )
            self.clean_up()
            return response

    def log_request(self, context: ExtendedContext, msg: str, level: Optional[str] = "info"):
        _msg = 20*"=" + f"{msg}: {context.request}" + 20*"="
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
        _entity_type = self.upstream_get("unit")
        persistence = getattr(_entity_type, "persistence", None)
        if persistence:
            persistence.flush_session_manager()

    def load_cdb(self, context: ExtendedContext, client_id: Optional[str] = "",
                 entity_id: Optional[str] = "") -> dict:
        """
        Guesses the client_id from parts of the request, then uses local storage and updates the
        client DB
        This is not a validation just a client detection
        Validation is demanded later by idpy_oidc parse_request
        """

        # The simple thing get it from the request
        if not client_id:
            if context.request and isinstance(context.request, (dict, Message)):
                client_id = context.request.get("client_id")

        logger.debug("client_id in request")
        # Get the AS part of this entity
        _frontend = self.upstream_get("unit")
        _srv = _frontend.pick_guise('openid_provider')
        if not _srv:
            _srv = _frontend.pick_guise('oauth_authorization_server')
        # Use that to get the appropriate persistence layer
        _persistence = _srv.persistence

        if client_id:
            client_info = _persistence.restore_client_info(client_id)
        else:
            client_info = {}
            if "Basic " in getattr(context, "request_authorization", ""):
                logger.debug(f"client_id from basic authentication")
                # here even for introspection endpoint
                client_info = _persistence.restore_client_info_by_basic_auth(
                    context.request_authorization) or {}
                client_id = client_info.get("client_id")

            elif context.request and context.request.get("code"):  # pragma: no cover
                logger.debug(f"client_id from access code")
                _persistence.restore_session_info()
                client_id = _srv.context.session_manager.get_client_id_from_token(
                    context.request.get("code"), handler_key="authorization_code")
                logger.debug(f"Client ID: {client_id}")
                client_info = _persistence.restore_client_info(client_id)
                client_id = client_info.get("client_id", "")
                entity_id = client_info.get("entity_id", "")

            elif context.request and context.request.get("client_assertion"):  # pragma: no cover
                logger.debug(f"client_id from client_assertion")
                token = AuthnToken().from_jwt(
                    txt=context.request["client_assertion"],
                    keyjar=KeyJar(),  # keyless keyjar
                    verify=False,  # otherwise keyjar MUST contain the issuer key
                )
                entity_id = token.get("iss")
                client_info = _persistence.restore_client_info(entity_id)

            elif "Bearer " in getattr(context, "request_authorization", ""):
                logger.debug(f"client_id from bearer token")
                client_info = _persistence.restore_client_info_by_bearer_token(
                    context.request_authorization) or {}
                client_id = client_info.get("client_id", "")
                entity_id = client_info.get("entity_id", "")
            elif "OAuth-Client-Attestation-PoP" in context.https_headers:
                logger.debug(f"client_id from OAuth-Client-Attestation-PoP HTTP header")
                _jws = factory(context.https_headers["OAuth-Client-Attestation-PoP"])
                if _jws:
                    client_id = _jws.jwt.payload()["iss"]
                    client_info = _persistence.restore_client_info(client_id) or {}
                    client_id = client_info.get("client_id", "")
                    entity_id = client_info.get("entity_id", "")
            else:  # pragma: no cover
                _srv.context.cdb = {}
                _msg = f"Client {client_id} not found!"
                logger.warning(_msg)
                raise InvalidClient(_msg)

        if client_info:
            logger.debug(f"Loaded oidcop client: {client_info}")
        else:  # pragma: no cover
            _url = urlparse(client_id)
            if _url.scheme not in ["http", "https"]:
                _srv.context.cdb = client_info = {client_id: {"client_id": client_id}}
                return client_info

            logger.info(f'Cannot find "{client_id}" in client DB')
            # _federation_entity = get_federation_entity(self)
            _federation_entity = self.upstream_get("unit").app.server["federation_entity"]

            if entity_id:
                trust_chains = get_verified_trust_chains(_federation_entity, entity_id=entity_id)
            else:
                trust_chains = get_verified_trust_chains(_federation_entity, client_id)

            if trust_chains:
                _federation_entity.store_trust_chains(client_id, trust_chains)
                client_info = trust_chains[0].metadata["openid_relying_party"]
                _srv.context.cdb = {client_id: client_info}
            else:
                raise UnknownClient(client_id)

        _jwks_uri = client_info.get("jwks_uri", None)
        if _jwks_uri:
            _srv.context.keyjar.load_keys(client_id, jwks_uri=_jwks_uri)
        else:
            _jwks = client_info.get("jwks", None)
            if _jwks:
                _srv.context.keyjar = import_jwks(_srv.context.keyjar, _jwks, client_id)

        # BUT specs are against!
        # https://openid.net/specs/openid-connect-registration-1_0.html#ReadRequest
        _rat = client_info.get("registration_access_token")
        if _rat:
            _srv.context.registration_access_token[_rat] = client_info["client_id"]
        else:
            _srv.context.registration_access_token = {}
        return client_info


def get_endpoint_wrapper(endpoint: Endpoint, endpoint_wrapper_path=None):
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


def get_special_endpoint_wrapper(path, endpoint_name):
    try:
        module = importlib.import_module(f"{path}.{endpoint_name}")
        clsmembers = inspect.getmembers(module, inspect.isclass)
        for name, cls in clsmembers:
            if name.endswith("EndpointWrapper"):
                if endpoint_name in cls.wraps:
                    return cls
    except Exception as err:
        return None
    else:
        return module
