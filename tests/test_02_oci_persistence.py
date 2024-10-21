import base64
import os
import shutil
from typing import Optional

import pytest
from cryptojwt.key_jar import init_key_jar
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.message.oidc import AccessTokenRequest
from idpyoidc.message.oidc import AuthorizationRequest
from idpyoidc.server.authn_event import create_authn_event
from satosa_idpyop.utils import combine_client_subject_id
from satosa_openid4vci.openid_credential_issuer import OpenidCredentialIssuer

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


CRYPT_CONFIG = {
    "kwargs": {
        "keys": {
            "key_defs": [
                {"type": "OCT", "use": ["enc"], "kid": "password"},
                {"type": "OCT", "use": ["enc"], "kid": "salt"},
            ]
        },
        "iterations": 1,
    }
}

SESSION_PARAMS = {"encrypter": CRYPT_CONFIG}

AUTH_REQ = AuthorizationRequest(
    client_id="client_1",
    redirect_uri="https://example.com/cb",
    scope=["openid"],
    state="STATE_ABC",
    response_type="code",
)

TOKEN_REQ = AccessTokenRequest(
    client_id="client_1",
    redirect_uri="https://example.com/cb",
    state="STATE_ABC",
    grant_type="authorization_code",
    client_secret="hemligt",
)

AUTH_REQ_2 = AuthorizationRequest(
    client_id="client_2",
    redirect_uri="https://client2.example.org/callback",
    scope=["openid"],
    state="STATE_XYZ",
    response_type="code",
)

CLIENT_INFO_1 = {
    "client_id": "client_1",
    "client_secret": "paaaasssswoord",
    "redirect_uris": [
        "https://client.example.org/callback",
        "https://client.example.org/callback2",
    ],
    "token_endpoint_auth_method": "client_secret_basic",
    "jwks_uri": "https://client.example.org/my_public_keys.jwks",
    "contacts": ["ve7jtb@example.org", "mary@example.org"],
}
KEYJAR_1 = init_key_jar(key_defs=DEFAULT_KEY_DEFS)

CLIENT_INFO_2 = {
    "client_id": "client_2",
    "client_secret": "ssseeeccrettt",
    "redirect_uris": [
        "https://client2.example.org/callback",
        "https://client2.example.org/callback2",
    ],
    "token_endpoint_auth_method": "client_secret_basic",
    "jwks_uri": "https://client2.example.org/jwks.json"
}
KEYJAR_2 = init_key_jar(key_defs=DEFAULT_KEY_DEFS)


@pytest.fixture
def server_conf():
    return {
        "entity_id": "https://example.com/",
        "token_expires_in": 600,
        "grant_expires_in": 300,
        "refresh_token_expires_in": 86400,
        "keys": {"key_defs": DEFAULT_KEY_DEFS, "uri_path": "static/jwks.json"},
        "jwks_uri": "https://example.com/jwks.json",
        "httpc_params": {"verify": False, "timeout": 33},
        "token_handler_args": {
            "jwks_def": {
                "private_path": "private/token_jwks.json",
                "read_only": False,
                "key_defs": [{"type": "oct", "bytes": "24", "use": ["enc"], "kid": "code"}],
            },
            "code": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
            "token": {
                "class": "idpyoidc.server.token.jwt_token.JWTToken",
                "kwargs": {
                    "lifetime": 3600,
                    "add_claims": True,
                    "add_claims_by_scope": True,
                    "aud": ["https://example.org/appl"],
                },
            },
            "refresh": {
                "class": "idpyoidc.server.token.jwt_token.JWTToken",
                "kwargs": {
                    "lifetime": 3600,
                    "aud": ["https://example.org/appl"],
                },
            },
            "id_token": {
                "class": "idpyoidc.server.token.id_token.IDToken",
                "kwargs": {
                    "base_claims": {
                        "email": {"essential": True},
                        "email_verified": {"essential": True},
                    }
                },
            },
        },
        "persistence": {
            "class": "satosa_idpyop.persistence.openid_provider.OPPersistence",
            "kwargs": {
                "storage": {
                    "class": "satosa_idpyop.core.storage.file.FilesystemDB",
                    "kwargs": {
                        "fdir": "op_storage",
                        "key_conv": "idpyoidc.util.Base64",
                        "value_conv": "idpyoidc.util.JSON"
                    }
                }
            }
        },
        "session_params": SESSION_PARAMS,
        "template_dir": "template",
        "claims_interface": {
            "class": "idpyoidc.server.session.claims.ClaimsInterface",
            "kwargs": {},
        },
        "userinfo": {
            "class": "idpyoidc.server.user_info.UserInfo",
            "kwargs": {"db_file": full_path("users.json")},
        }
    }


class TestOCIPersistence(object):

    @pytest.fixture(autouse=True)
    def create_persistence_layer(self, server_conf):
        # clean up after last time
        try:
            shutil.rmtree("op_storage")
            shutil.rmtree("fe_storage")
        except FileNotFoundError:
            pass

        self.server = OpenidCredentialIssuer(server_conf)

        self.user_id = "diana"

    def _create_session(self, auth_req, sub_type="public", sector_identifier="",
                        user_id: Optional[str] = "diana"):
        if sector_identifier:
            authz_req = auth_req.copy()
            authz_req["sector_identifier_uri"] = sector_identifier
        else:
            authz_req = auth_req

        client_id = authz_req["client_id"]
        ae = create_authn_event(user_id)
        return self.server.context.session_manager.create_session(
            ae, authz_req, user_id, client_id=client_id, sub_type=sub_type
        )

    def _mint_code(self, grant, session_id):
        _server = self.server
        _sman = _server.context.session_manager
        # Constructing an authorization code is now done
        _code = grant.mint_token(
            session_id,
            context=_server.context,
            token_class="authorization_code",
            token_handler=_sman.token_handler["authorization_code"]
        )

        _sman.set(_sman.decrypt_session_id(session_id), grant)

        return _code

    def _mint_access_token(self, grant, session_id, token_ref=None):
        _server = self.server
        _sman = _server.context.session_manager
        _session_info = _sman.get_session_info(session_id, client_session_info=True)

        _token = grant.mint_token(
            session_id=session_id,
            context=_server.context,
            token_class="access_token",
            token_handler=_sman.token_handler["access_token"],
            based_on=token_ref,  # Means the token (token_ref) was used to mint this token
        )

        _sman.set([self.user_id, _session_info["client_id"], grant.id], grant)

        return _token

    def _client_registration(self,
                             client_info: dict,
                             jwks: Optional[dict] = None,
                             jwks_uri: Optional[str] = ""):
        _context = self.server.context
        _context.cdb[client_info["client_id"]] = client_info
        if jwks:
            _context.keyjar.import_jwks(jwks, client_info["client_id"])
        if jwks_uri:
            pass

    def test_claims(self):
        claims = {
            "name": "Diana Krall",
            "given_name": "Diana",
            "family_name": "Krall",
            "nickname": "Dina",
        }
        client_subject_id = combine_client_subject_id("client_1", "diana")
        self.server.persistence.store_claims(claims, client_subject_id)

        _claims = self.server.persistence.load_claims(client_subject_id)
        assert claims == _claims

        sid = self._create_session(auth_req=AUTH_REQ)
        _claims2 = self.server.persistence.get_claims_from_branch_key(sid)
        assert _claims2 == _claims
        assert _claims2 == claims

    def test_client(self):
        self._client_registration(CLIENT_INFO_1, jwks=KEYJAR_1.export_jwks())
        self.server.persistence.store_client_info(CLIENT_INFO_1["client_id"])

        _context = self.server.context
        self.server.persistence.restore_client_info(CLIENT_INFO_1["client_id"])
        assert _context.cdb[CLIENT_INFO_1["client_id"]] == CLIENT_INFO_1

        _context.cdb = {}
        credentials = f"{CLIENT_INFO_1['client_id']}:{CLIENT_INFO_1['client_secret']}"
        token = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")
        authz = f"Basic {token}"
        self.server.persistence.restore_client_info_by_basic_auth(authz)
        assert _context.cdb[CLIENT_INFO_1["client_id"]] == CLIENT_INFO_1

        _context.cdb = {}
        session_id = self._create_session(AUTH_REQ)
        grant = self.server.context.authz(session_id, AUTH_REQ)
        code = self._mint_code(grant, session_id)
        access_token = self._mint_access_token(grant, session_id, code)
        self.server.persistence.restore_client_info_by_bearer_token(f"Bearer {access_token.value}")
        assert _context.cdb[CLIENT_INFO_1["client_id"]] == CLIENT_INFO_1

    def test_get_registered_client_ids(self):
        self._client_registration(CLIENT_INFO_1, jwks=KEYJAR_1.export_jwks())
        self.server.persistence.store_client_info(CLIENT_INFO_1["client_id"])
        self._client_registration(CLIENT_INFO_2, jwks=KEYJAR_2.export_jwks())
        self.server.persistence.store_client_info(CLIENT_INFO_2["client_id"])

        clients = self.server.persistence.get_registered_client_ids()
        assert set(clients) == {"client_1", "client_2"}

    def test_state(self):
        # Same user from different clients
        # First state change
        self._client_registration(CLIENT_INFO_1, jwks=KEYJAR_1.export_jwks())

        session_id = self._create_session(AUTH_REQ)
        grant = self.server.context.authz(session_id, AUTH_REQ)
        code_1 = self._mint_code(grant, session_id)
        self.server.persistence.store_state('client_1')

        self.server.persistence.flush_session_manager()

        # Second state change
        self._client_registration(CLIENT_INFO_2, jwks=KEYJAR_2.export_jwks())
        session_id = self._create_session(AUTH_REQ_2)
        grant = self.server.context.authz(session_id, AUTH_REQ_2)
        code_2 = self._mint_code(grant, session_id)
        self.server.persistence.store_state('client_2')

        self.server.persistence.reset_state()

        _request = TOKEN_REQ.copy()
        _request["code"] = code_1.value
        credentials = f"{CLIENT_INFO_1['client_id']}:CLIENT_INFO_1['client_secret']"
        token = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")
        http_info = {"headers": {"authorization": f"Basic {token}"}}
        self.server.persistence.restore_state(request=_request, http_info=http_info)

        assert set(self.server.context.cdb.keys()) == {"client_1"}
        assert len(self.server.context.session_manager.db.db.keys()) == 3
        assert 'diana' in self.server.context.session_manager.db.db
        assert 'diana;;client_1' in self.server.context.session_manager.db.db
        assert self.server.keyjar.httpc_params["timeout"] == 10
        assert self.server.context.keyjar.httpc_params["timeout"] == 10
