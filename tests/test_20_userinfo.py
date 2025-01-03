import os
import re
import sys
from typing import Optional
import urllib

from idpyoidc.message import Message
from idpyoidc.message.oauth2 import AuthorizationRequest
from idpyoidc.server.user_authn.authn_context import PASSWORD
from idpyoidc.util import load_yaml_config
from idpyoidc.util import rndstr
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
from tests import clear_folder
from tests import create_trust_chain_messages
from tests import federation_setup
from tests.users import USERS

BASEDIR = os.path.abspath(os.path.dirname(__file__))
INTERNAL_ATTRIBUTES = {
    "attributes": {"mail": {"saml": ["email"], "openid": ["email"]}}
}
OP_BASE_URL = "https://op.example.com"

sys.path.insert(0, ".")


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


def auth_req_callback_func(c, x):
    return x


class TestFrontEnd():

    @pytest.fixture(autouse=True)
    def federation_setup(self):
        # Dictionary with all the federation members
        self.entity = federation_setup()

    @pytest.fixture
    def frontend(self):
        clear_folder("op_storage")
        clear_folder("fe_storage")
        frontend_config = load_yaml_config(full_path("satosa_conf.yaml"))

        frontend_config["op"]["server_info"]["entity_type"]["openid_provider"]["kwargs"]["config"][
            "userinfo"] = {
            "class": "satosa_idpyop.user_info.ProxyUserInfo",
            "kwargs": {}
        }

        _keys = self.entity["trust_anchor"].keyjar.export_jwks()
        frontend_config["op"]["server_info"]["trust_anchors"]["https://ta.example.org"]["keys"] = \
        _keys["keys"]
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
            "saml",
            USERS["testuser1"])
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

    def _token_flow(self, client, context, frontend, response_part, state, authz_request, **kwargs):
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

    def _userinfo_flow(self, client, context, frontend, **kwargs):
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

    def test_flow(self, frontend, context):
        client = self.entity["relying_party"]["openid_relying_party"]
        client.context.issuer = OP_BASE_URL
        self._discovery(client, context, frontend)

        # Create authorization request
        authz_request = {
            'response_type': 'code',
            'client_id': client.entity_id,
            "redirect_uri": client.context.claims.get_preference("redirect_uris")[0],
            "nonce": rndstr(),
            "scope": ["openid", "email", "profile"]
        }

        _state = rndstr()
        kwargs = {"state": _state}

        _service = client.get_service("authorization")
        req_info = _service.get_request_parameters(authz_request, **kwargs)

        assert req_info
        assert set(req_info.keys()) == {"method", "request", "url"}

        context.request = req_info["request"]
        context.request_uri = req_info["url"]
        context.request_method = req_info["method"]
        context.http_info = {"headers": {}}

        # ---- Switch to the server side. The SATOSA frontend

        func = self._find_endpoint(frontend, "authorization")

        # All the federation stuff should be cached
        where_and_what = create_trust_chain_messages(self.entity["relying_party"],
                                                     self.entity["trust_anchor"])

        del where_and_what['https://rp.example.org/.well-known/openid-federation']
        del where_and_what['https://ta.example.org/.well-known/openid-federation']
        del where_and_what['https://ta.example.org/fetch']

        with responses.RequestsMock() as rsps:
            for _url, _jwks in where_and_what.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/entity_statement+jwt"},
                         status=200)

            _parsed_req = func(context)

        internal_response = self.setup_for_authn_response(context, frontend,
                                                          AuthorizationRequest(**authz_request))
        _auth_response = frontend.handle_authn_response(context, internal_response)

        assert isinstance(_auth_response, SeeOther)
        _part = urllib.parse.parse_qs(_auth_response.message.split("?")[1])

        #  token endpoint
        self._token_flow(client, context, frontend, _part, _state, authz_request)

        response = self._userinfo_flow(client, context, frontend, state=_state)
        assert response
