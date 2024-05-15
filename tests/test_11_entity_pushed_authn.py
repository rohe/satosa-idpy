import os
import re
import shutil
import sys
from typing import Optional
import urllib.parse

from idpyoidc.message import Message
from idpyoidc.message.oidc import AuthorizationRequest
from idpyoidc.server.user_authn.authn_context import PASSWORD
from idpyoidc.util import load_yaml_config
from idpyoidc.util import rndstr
# from openid4v.client.client_authn import ClientAuthenticationAttestation
import pytest
import responses
from satosa.attribute_mapping import AttributeMapper
from satosa.frontends.base import FrontendModule
from satosa.internal import AuthenticationInformation
from satosa.internal import InternalData
from satosa.response import SeeOther
from satosa.state import State

from satosa_idpyop.core import ExtendedContext
from satosa_idpyop.endpoint_wrapper import EndPointWrapper
from satosa_idpyop.idpyop import IdpyOPFrontend
from tests import TA_ID
from tests import create_trust_chain_messages
from tests import federation_pushed_authn_setup
from tests.users import USERS

BASEDIR = os.path.abspath(os.path.dirname(__file__))

sys.path.insert(0, ".")


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


INTERNAL_ATTRIBUTES = {
    "attributes": {"mail": {"saml": ["email"], "openid": ["email"]}}
}

OP_BASE_URL = "https://op.example.com"


def auth_req_callback_func(c, x):
    return x


def clear_folder(folder):
    for root, dirs, files in os.walk(f'{full_path(folder)}'):
        for f in files:
            os.unlink(os.path.join(root, f))
        for d in dirs:
            shutil.rmtree(os.path.join(root, d))


class TestFrontEnd():

    @pytest.fixture(autouse=True)
    def federation_setup(self):
        # Dictionary with all the federation members
        self.entity = federation_pushed_authn_setup()

    @pytest.fixture
    def frontend(self):
        clear_folder("op_storage")
        frontend_config = load_yaml_config(full_path("satosa_conf_pa.yaml"))

        _keys = self.entity["trust_anchor"].keyjar.export_jwks()
        frontend_config["op"]["server_info"]["trust_anchors"][TA_ID]["keys"] = _keys["keys"]
        frontend = IdpyOPFrontend(auth_req_callback_func, INTERNAL_ATTRIBUTES,
                                  frontend_config, OP_BASE_URL, "idpyop_frontend")
        url_map = frontend.register_endpoints([])
        return frontend

    @pytest.fixture
    def context(self):
        context = ExtendedContext()
        context.state = State()
        return context

    def setup_for_authn_response(self, context: ExtendedContext, frontend: FrontendModule,
                                 auth_req: Message):
        context.state[frontend.name] = {"oidc_request": auth_req.to_urlencoded()}

        auth_info = AuthenticationInformation(
            PASSWORD, "2015-09-30T12:21:37Z", "unittest_idp.xml"
        )
        internal_response = InternalData(auth_info=auth_info)
        internal_response.attributes = AttributeMapper(frontend.internal_attributes).to_internal(
            "saml", USERS["testuser1"])
        internal_response.subject_id = USERS["testuser1"]["eduPersonTargetedID"][0]

        return internal_response

    def _find_endpoint(self, frontend, endpoint_path) -> Optional[EndPointWrapper]:
        for pattern, endp in frontend.endpoints:
            if re.search(pattern, endpoint_path):
                return endp
        return None

    def _discovery(self, client, context, frontend):
        # client side
        _provider_config_service = client.get_service("provider_info")
        req_info = _provider_config_service.get_request_parameters()

        # Server side
        context.request = {}
        context.request_uri = req_info["url"]
        context.request_method = req_info["method"]
        context.http_info = {"headers": {}}

        func = self._find_endpoint(frontend, ".well-known/openid-configuration")
        response = func(context)

        # back at the client side
        resp = _provider_config_service.parse_response(response.message)
        jwks_func = self._find_endpoint(frontend, "static/jwks.json")
        _keys = jwks_func()
        with responses.RequestsMock() as rsps:
            rsps.add("GET", "https://op.example.com/static/jwks.json",
                     body=_keys.message,
                     adding_headers={"Content-Type": "application/json"}, status=200)

            _provider_config_service.update_service_context(resp)

    def _authz(self, client, context, frontend):
        authz_request = {
            'response_type': 'code',
            'client_id': client.entity_id,
            "redirect_uri": client.context.claims.get_preference("redirect_uris")[0],
            "nonce": rndstr(),
            "scope": ["openid"]
        }

        _service = client.get_service("authorization")
        _context = _service.upstream_get("context")
        _state = _context.cstate.create_state(iss=_context.get("issuer"))
        _context.cstate.bind_key(authz_request["nonce"], _state)
        authz_request["state"] = _state
        _context.cstate.update(_state, authz_request)

        # server side
        ca = client.context.client_authn_methods["private_key_jwt"]
        _req = AuthorizationRequest(**authz_request)
        _aud = client.context.provider_info['pushed_authorization_request_endpoint']
        ca.construct(_req, _service, audience=_aud)
        context.request = _req
        context.request_uri = _aud
        context.request_method = "POST"
        context.http_info = {"headers": {}}

        func = self._find_endpoint(frontend, "pushed_authorization")
        where_and_what = create_trust_chain_messages(self.entity["relying_party"],
                                                     self.entity["trust_anchor"])

        with responses.RequestsMock() as rsps:
            for _url, _jwks in where_and_what.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            resp = func(context)

        # response from Pushed Authz endpoint

        _authz_req = AuthorizationRequest().from_json(resp.message)
        _authz_req["scope"] = authz_request["scope"]
        _authz_req["redirect_uri"] = authz_request["redirect_uri"]
        _authz_req["client_id"] = authz_request["client_id"]
        _authz_req["response_type"] = authz_request["response_type"]
        del _authz_req["expires_in"]

        context.request = _authz_req
        context.request_uri = client.context.provider_info['authorization_endpoint']
        context.request_method = "GET"
        context.http_info = {"headers": {}}

        # ---- Switch to the server side. The SATOSA frontend authz endpoint
        func = self._find_endpoint(frontend, "authorization")
        _parsed_req = func(context)

        internal_response = self.setup_for_authn_response(context, frontend, _authz_req)
        _auth_response = frontend.handle_authn_response(context, internal_response)

        assert isinstance(_auth_response, SeeOther)
        return _auth_response, authz_request

    def _token(self, client, context, frontend, response_part, state, authz_request, **kwargs):
        token_request = {
            'grant_type': 'authorization_code',
            'code': response_part["code"][0],
            'redirect_uri': authz_request["redirect_uri"],
            'client_id': client.entity_id,
            'state': state,
        }

        _service = client.get_service("accesstoken")
        req_info = _service.get_request_parameters(token_request,
                                                   authn_method="private_key_jwt",
                                                   **kwargs)

        # ---- Switch to the server side.

        context.http_info = req_info["headers"]
        context.request_method = req_info["method"]
        context.request_uri = req_info["url"]
        context.request = req_info["request"]

        func = self._find_endpoint(frontend, "token")

        response = func(context)

        # back at the client side
        resp = _service.parse_response(response.message)
        _service.update_service_context(resp, state)

    def _userinfo(self, client, context, frontend, **kwargs):
        userinfo_request = {}
        _service = client.get_service("userinfo")
        _req_info = _service.get_request_parameters(userinfo_request, **kwargs)

        # ---- Switch to the server side. The PID issuer

        context.request = {}
        context.request_uri = _req_info["url"]
        context.request_method = _req_info["method"]
        context.http_info = _req_info["headers"]

        func = self._find_endpoint(frontend, "userinfo")

        response = func(context)
        return response.message

    def _find_endpoint(self, frontend, endpoint_path) -> Optional[EndPointWrapper]:
        for pattern, endp in frontend.endpoints:
            if re.search(pattern, endpoint_path):
                return endp
        return None

    def test_flow(self, frontend, context):
        client = self.entity["relying_party"]["openid_relying_party"]
        client.context.issuer = OP_BASE_URL

        # Provider Info discovery endpoint
        self._discovery(client, context, frontend)

        # Authz request endpoint
        _auth_response, authz_request = self._authz(client, context, frontend)
        _state = authz_request["state"]

        #  token endpoint
        _part = urllib.parse.parse_qs(_auth_response.message.split("?")[1])
        self._token(client, context, frontend, _part, _state, authz_request)

        # User Info endpoint
        response = self._userinfo(client, context, frontend, state=_state)
        assert response
