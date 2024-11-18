import base64
import logging
from typing import Optional
from typing import Union

from cryptojwt import as_unicode
from cryptojwt import JWT
from cryptojwt import KeyBundle
from cryptojwt import KeyJar
from cryptojwt.exception import BadSignature
from cryptojwt.exception import Invalid
from cryptojwt.exception import MissingKey
from cryptojwt.jws.jws import factory
from cryptojwt.utils import as_bytes
from idpyoidc.key_import import import_jwks
from idpyoidc.message import Message
from idpyoidc.message.oidc import JsonWebToken
from idpyoidc.server.client_authn import basic_authn
from idpyoidc.server.exception import ClientAuthenticationError
from idpyoidc.util import sanitize
from openid4v.message import AuthorizationRequest

from satosa_idpyop.persistence import Persistence
from satosa_idpyop.utils import combine_client_subject_id

logger = logging.getLogger(__name__)


# Doesn't know about ExtendedContext

class OPPersistence(Persistence):
    name = "openid_provider"

    def __init__(self, storage, upstream_get):
        super(OPPersistence, self).__init__(storage, upstream_get)

    def flush_session_manager(self, session_manager=None):
        """
        each OAuth2/OIDC request loads an oidcop session in memory
        this method will simply free the memory from any loaded session
        """
        if not session_manager:
            session_manager = self.upstream_get("context").session_manager

        session_manager.flush()

    def reset_state(self):
        _session_manager = self.upstream_get("context").session_manager
        self.flush_session_manager(_session_manager)
        _context = self.upstream_get("context")
        _context.cdb = {}
        # Get rid of all keys apart from my own by creating a new keyjar with only my keys
        jwks_1 = _context.keyjar.export_jwks(private=True, issuer_id="")
        jwks_2 = _context.keyjar.export_jwks(private=True, issuer_id=_context.entity_id)
        keyjar = KeyJar()
        keyjar = import_jwks(keyjar, jwks_1, "")
        unit = self.upstream_get("unit")
        unit.keyjar = keyjar
        _context.keyjar = unit.keyjar

    def _deal_with_client_assertion(self, sman, token):
        _keyjar = sman.upstream_get("attribute", "keyjar")
        _jwt = JWT(_keyjar)
        _jwt.msg_cls = JsonWebToken
        try:
            ca_jwt = _jwt.unpack(token)
        except (Invalid, MissingKey, BadSignature) as err:
            logger.info("[OP_PS] %s" % sanitize(err))
            raise ClientAuthenticationError("Could not verify client_assertion.")
        return ca_jwt["iss"]

    def _get_client_id(self,
                       session_manager,
                       request: Union[Message, dict],
                       http_info: dict) -> Optional[str]:
        # Figure out which client is concerned
        if "client_id" in request:
            return request["client_id"]

        for param in ["code", "access_token", "refresh_token", "registration_access_token"]:
            if param in request:
                _token_info = session_manager.token_handler.info(request[param])
                sid = _token_info["sid"]
                _path = session_manager.decrypt_branch_id(sid)
                return _path[1]

        if "client_assertion" in request:
            return self._deal_with_client_assertion(session_manager, request["client_assertion"])

        authz = http_info.get("headers", {}).get("authorization", "")
        if authz:
            if "Basic " in authz:
                token = authz.split(" ", 1)[1]
                _info = basic_authn(token)
                return _info["id"]
            else:
                token = authz.split(" ", 1)[1]
                # is the token a default token or a signed JWT
                _jws = factory(token)
                if _jws:
                    return _jws.jwt.payload().get("client_id", "")
                else:
                    _token_info = session_manager.token_handler.info(token)
                    sid = _token_info["sid"]
                    _path = session_manager.decrypt_branch_id(sid)
                    return _path[1]

        return None

    def restore_session_info(self):
        logger.debug(f"[OP_PS] Restore general session info")
        _context = self.upstream_get("context")
        sman = _context.session_manager
        _session_info = self.storage.fetch(information_type="session_info", key="")
        logger.debug(f"[OP_PS] Fetched session_info: {_session_info}")
        self.flush_session_manager(sman)
        if _session_info:
            sman.load(_session_info)
        return sman, _session_info

    def restore_state(self,
                      request: Union[Message, dict],
                      http_info: Optional[dict]):
        sman, _session_info = self.restore_session_info()

        # Find the client_id
        client_id = self._get_client_id(sman, request=request, http_info=http_info)
        logger.debug(f"[OP_PS] Restore state for '{client_id}'")
        # Update session
        _client_session_info = self.storage.fetch(information_type="client_session_info",
                                                  key=client_id)
        if _client_session_info is None:
            _client_session_info = {}

        if _session_info:
            _session_info["db"] = _client_session_info

        self.flush_session_manager(sman)

        logger.debug(f"[OP_PS] _session_info: {_session_info}")
        if _session_info:
            sman.load(_session_info)

        # Update client database
        self.restore_client_info(client_id)
        self.restore_keys()

    def load_claims(self, client_subject_id: str):
        return self.storage.fetch(information_type="claims", key=client_subject_id)

    # Now for the store part

    def store_claims(self, claims: dict, client_subject_id: str):
        self.storage.store(information_type="claims", value=claims, key=client_subject_id)

    def _get_client_session_info(self, client_id, db):
        sman = self.upstream_get("context").session_manager
        res = {}
        for key, info in db.items():
            val = sman.unpack_branch_key(key)
            if len(val) > 1 and val[1] == client_id:
                res[key] = info
                if val[0] not in res:
                    res[val[0]] = db[val[0]]
        return res

    def store_state(self, client_id: Optional[str] = ""):
        if client_id:
            logger.debug(f"[OP_PS] Store state for {client_id}")
        else:
            logger.debug(f"[OP_PS] Store no client related session information")

        sman = self.upstream_get("context").session_manager
        _session_state = sman.dump()
        if client_id:
            _client_session_info = self._get_client_session_info(client_id, _session_state["db"])
            self.storage.store(information_type="client_session_info",
                               value=_client_session_info,
                               key=client_id)
            self.store_client_info(client_id)
        _session_state["db"] = {}
        self.storage.store(information_type="session_info", value=_session_state)
        self.store_keys()

    def store_client_info(self, client_id):
        logger.debug(f"[OP_PS] store_client_info: {client_id}")
        _context = self.upstream_get("context")
        logger.debug(f"Storing client info: {_context.cdb[client_id]}")
        # client info?
        self.storage.store(information_type="client_info", key=client_id,
                           value=_context.cdb[client_id])
        # client keys
        self.storage.store(information_type="jwks", key=client_id,
                           value=_context.keyjar.export_jwks(issuer=client_id))

    def restore_client_info(self, client_id: str) -> dict:
        logger.debug(f"[OP_PS] restore_client_info: '{client_id}'")
        _context = self.upstream_get("context")
        client_info = self.storage.fetch(information_type="client_info", key=client_id)
        if client_info is None:
            client_info = {}
        _context.cdb[client_id] = client_info
        jwks = self.storage.fetch(information_type="jwks", key=client_id)
        if jwks:
            _context.keyjar = import_jwks(_context.keyjar, jwks, client_id)
        return client_info

    def restore_client_info_by_bearer_token(self, request_authorization: str):
        access_token = request_authorization.replace("Bearer ", "")
        sman = self.upstream_get("context").session_manager
        _session_info = sman.get_session_info_by_token(
            access_token, grant=True, handler_key="access_token"
        )
        return self.restore_client_info(_session_info["client_id"])

    def restore_client_info_by_access_code(self, code: str):
        sman = self.upstream_get("context").session_manager
        _session_info = sman.get_session_info_by_token(
            code, grant=True, handler_key="authorization_code"
        )
        return self.restore_client_info(_session_info["client_id"])

    def restore_client_info_by_basic_auth(self, http_authorization):
        _token = http_authorization.replace("Basic ", "")
        _tok = as_bytes(_token)
        # Will raise ValueError type exception if not base64 encoded
        _tok = base64.b64decode(_tok)
        part = as_unicode(_tok).split(":", 1)
        if len(part) != 2:
            raise ValueError("Illegal token")
        return self.restore_client_info(part[0])

    def get_claims_from_branch_key(self, branch_key):
        sman = self.upstream_get("context").session_manager
        _user_id, _client_id, _grant_id = sman.decrypt_branch_id(branch_key)
        _client_user_id = combine_client_subject_id(_client_id, _user_id)
        return self.storage.fetch(information_type="claims", key=_client_user_id)

    def get_registered_client_ids(self):
        return self.storage.keys_by_information_type("client_info")

    def load_all_claims(self, context=None):
        claims = {}
        _context = context or self.upstream_get("context")
        _userinfo = getattr(_context, "userinfo", None)
        if _userinfo is None:
            return

        sman = _context.session_manager

        for k, v in sman.dump()["db"].items():
            if v[0] == "idpyoidc.server.session.grant.Grant":
                branch_key = k
                claims = self.get_claims_from_branch_key(branch_key)
                break
            else:  # pragma: no cover
                continue

        if not claims:
            logger.warning(
                "[OP_PS] Can't find any suitable sid/claims from stored session"
            )

        # That's a patchy runtime definition of userinfo db configuration
        _userinfo.load(claims)

    def store_pushed_authorization(self):
        _context = self.upstream_get("context")
        par_db = getattr(_context, "par_db", None)
        _db = {}
        for k, v in par_db.items():
            if isinstance(v, Message):
                _db[k] = v.to_dict()
            else:
                _db[k] = v
        logger.debug(f"[OP_PS] store_pushed_authorization: {_db}")
        if _db:
            self.storage.store(information_type="par", value=_db)

    def restore_pushed_authorization(self):
        _context = self.upstream_get("context")
        _par = {}
        _information = self.storage.fetch(information_type="par")
        if _information:
            for _uri, v in _information.items():
                _par[_uri] = AuthorizationRequest(**v)

            logger.debug(f"[OP_PS] restore_pushed_authorization: {_par}")
            _context.par_db = _par

    def store_keys(self):
        _entity = self.upstream_get("unit")
        logger.debug(f"[OP_PS] Entity: {_entity.name}")
        logger.debug(f"[OP_PS]Stored keys belonging to: {_entity.context.keyjar.owners()}")
        _keyjar = getattr(_entity, 'keyjar')
        if _keyjar:
            logger.debug(f"[OP_PS] Other key owners: {_keyjar.owners()}")
        for entity_id in _entity.context.keyjar.owners():
            if entity_id == "" or entity_id == _entity.entity_id:
                jwks = _entity.context.keyjar.export_jwks(private=True, issuer_id=entity_id)
                if entity_id == "":
                    entity_id = "__"
            else:
                jwks = _entity.context.keyjar.export_jwks(issuer_id=entity_id)
            logger.debug(f"[OP_PS] store entity_id: {entity_id}, jwks: {jwks}")
            self.storage.store(information_type="jwks", key=entity_id, value=jwks)

    def restore_keys(self):
        keyjar = KeyJar()
        issuers = set()
        for entity_id in self.storage.keys_by_information_type("jwks"):
            jwks = self.storage.fetch(information_type="jwks", key=entity_id)
            if jwks:
                if entity_id == '__':
                    entity_id = ""
                keyjar = import_jwks(keyjar, jwks, entity_id)
                issuers.add(entity_id)
            else:
                logger.debug(f"[OP_PS] No jwks for {entity_id}")

        if keyjar:
            _guise = self.upstream_get("unit")
            _httpc_params = getattr(_guise, "httpc_params", None)
            if _httpc_params:
                keyjar.httpc_params = _httpc_params
            # The keyjar is in the context
            if not _guise.context.keyjar:
                _guise.context.keyjar = keyjar
                _guise.keyjar = keyjar
            else:
                for iss, ki_a in _guise.context.keyjar.items():
                    if iss in keyjar:
                        ki_b = keyjar[iss]
                        xtra_keys = []
                        curr_keys = ki_a.all_keys()
                        for key in ki_b.all_keys():
                            if key not in curr_keys:
                                xtra_keys.append(key)
                        if xtra_keys:
                            kb = KeyBundle()
                            for key in xtra_keys:
                                kb.append(key)
                            ki_a.add_kb(kb)

            logger.debug(f"[OP_PS] Restored keys for these owners: {keyjar.owners()}")
