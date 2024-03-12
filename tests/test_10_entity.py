import os
import re
import shutil
import sys
import urllib.parse
from typing import Optional

# from openid4v.client.client_authn import ClientAuthenticationAttestation
import pytest
import responses
from cryptojwt.jws.jws import factory
from idpyoidc.message import Message
from idpyoidc.message.oidc import AuthorizationRequest
from idpyoidc.server.user_authn.authn_context import PASSWORD
from idpyoidc.util import load_yaml_config
from idpyoidc.util import rndstr
from satosa.attribute_mapping import AttributeMapper
from satosa.frontends.base import FrontendModule
from satosa.internal import AuthenticationInformation
from satosa.internal import InternalData
from satosa.response import SeeOther
from satosa.state import State

from satosa_idpyop.core import ExtendedContext
from satosa_idpyop.endpoint_wrapper import EndPointWrapper
from satosa_idpyop.endpoint_wrapper import get_http_info
from satosa_idpyop.idpyop import IdpyOPFrontend
from tests import create_trust_chain_messages
from tests import federation_setup
from tests.users import USERS

BASEDIR = os.path.abspath(os.path.dirname(__file__))

sys.path.insert(0, ".")


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


INTERNAL_ATTRIBUTES = {
    "attributes": {"mail": {"saml": ["email"], "openid": ["email"]}}
}

BASE_URL = "https://rp.example.com"


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
        clear_folder("op_storage")
        # Dictionary with all the federation members
        self.entity = federation_setup()

    @pytest.fixture
    def frontend(self):
        frontend_config = load_yaml_config("satosa_conf.yaml")

        _keys = self.entity["trust_anchor"].keyjar.export_jwks()
        frontend_config["op"]["server_info"]["trust_anchors"]["https://ta.example.org"]["keys"] = _keys["keys"]
        frontend = IdpyOPFrontend(auth_req_callback_func, INTERNAL_ATTRIBUTES,
                                  frontend_config, BASE_URL, "idpyop_frontend")
        url_map = frontend.register_endpoints([])
        return frontend

    @pytest.fixture
    def context(self):
        context = ExtendedContext()
        context.state = State()
        return context

    def setup_for_authn_response(self, context: ExtendedContext, frontend: FrontendModule, auth_req: Message):
        context.state[frontend.name] = {"oidc_request": auth_req.to_urlencoded()}

        auth_info = AuthenticationInformation(
            PASSWORD, "2015-09-30T12:21:37Z", "unittest_idp.xml"
        )
        internal_response = InternalData(auth_info=auth_info)
        internal_response.attributes = AttributeMapper(
            frontend.internal_attributes
        ).to_internal("saml", USERS["testuser1"])
        internal_response.subject_id = USERS["testuser1"]["eduPersonTargetedID"][0]

        return internal_response

    def test_entity_configuration_endpoint(self, context, frontend):
        context.request = {}
        response = frontend.entity_configuration_endpoint(context)
        assert response
        _jws = factory(response.message)
        _payload = _jws.jwt.payload()
        assert _payload
        assert _payload["authority_hints"] == ["https://ta.example.org"]
        assert set(_payload["metadata"].keys()) == {"federation_entity", "openid_provider"}

    def _find_endpoint(self, frontend, endpoint_path) -> Optional[EndPointWrapper]:
        for pattern, endp in frontend.endpoints:
            if re.search(pattern, endpoint_path):
                return endp
        return None

    def test_flow(self, frontend, context):
        client = self.entity["relying_party"]["openid_relying_party"]

        _secret = client.context.get_preference("client_secret")

        # Create authorization request
        authz_request = {
            'response_type': 'code',
            'client_id': client.entity_id,
            'client_secret': _secret,
            "redirect_uri": client.context.claims.get_preference("redirect_uris")[0],
        }

        _state = rndstr()
        kwargs = {"state": _state}

        _service = client.get_service("authorization")
        req_info = _service.get_request_parameters(authz_request, **kwargs)

        assert req_info
        assert set(req_info.keys()) == {"method", "request", "url"}

        context.request = req_info["request"]

        # ---- Switch to the server side. The SATOSA frontend

        func = self._find_endpoint(frontend, "authorization")

        where_and_what = create_trust_chain_messages(self.entity["relying_party"],
                                                     self.entity["trust_anchor"])

        with responses.RequestsMock() as rsps:
            for _url, _jwks in where_and_what.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            _parsed_req = func(context)

        internal_response = self.setup_for_authn_response(context, frontend, AuthorizationRequest(**authz_request))
        _auth_response = frontend.handle_authn_response(context, internal_response)

        #  token endpoint
        # Create a new client attestation
        assert isinstance(_auth_response, SeeOther)
        _part = urllib.parse.parse_qs(_auth_response.message.split("?")[1])

        token_request = {
            'grant_type': 'authorization_code',
            'code': _part["code"][0],
            'redirect_uri': authz_request["redirect_uri"],
            'client_id': client.entity_id,
            'state': _state,
        }

        _service = client.get_service("accesstoken")
        req_info = _service.get_request_parameters(token_request, **kwargs)

        # ---- Switch to the server side. The PID issuer

        func = self._find_endpoint(frontend, "token")
        context.http_info = {
            "headers": {
                "headers": req_info["headers"]
            },
            "method": req_info["method"],
            "url": req_info["url"]
        }

        _http_info = get_http_info(context)
        _parsed_req = func.parse_request(request=req_info["request"], http_info=_http_info)
        _token_response = func.process_request(context, _parsed_req, http_info=_http_info)
        assert _token_response
        _service.upstream_get("context").cstate.update(_state, _token_response["response_args"])

        userinfo_request = {}
        _service = client.get_service("userinfo")
        _req_info = _service.get_request_parameters(userinfo_request, **kwargs)

        assert req_info

        # ---- Switch to the server side. The PID issuer

        func = self._find_endpoint(frontend, "userinfo")

        _http_info = {
            "headers": req_info["headers"],
            "method": req_info["method"],
            "url": req_info["url"],
        }

        _parsed_req = func.parse_request(request=req_info["request"], http_info=_http_info)
        response = func.process_request(context, _parsed_req, http_info=_http_info)
        assert response
