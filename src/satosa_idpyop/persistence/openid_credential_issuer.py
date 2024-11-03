import logging
from typing import Optional
from typing import Union

from cryptojwt import KeyBundle
from cryptojwt import KeyJar
from idpyoidc.key_import import import_jwks
from idpyoidc.message import Message

from satosa_idpyop.persistence import Persistence

logger = logging.getLogger(__name__)


# Doesn't know about ExtendedContext

class OCIPersistence(Persistence):
    name = "openid_credential_issuer"

    def __init__(self, storage, upstream_get):
        super(OCIPersistence, self).__init__(storage, upstream_get)

    def flush_session_manager(self):
        return

    def reset_state(self):
        _context = self.upstream_get("context")
        # Get rid of all keys apart from my own by creating a new key jar with only my keys
        keyjar = KeyJar()
        for _id in ["", _context.entity_id]:
            _jwk = _context.keyjar.export_jwks(private=True, issuer_id=_id)
            keyjar = import_jwks(keyjar, _jwk, _id)

        unit = self.upstream_get("unit")
        unit.keyjar = keyjar
        _context.keyjar = unit.keyjar

    def restore_state(self,
                      request: Union[Message, dict],
                      http_info: Optional[dict]):
        self.restore_keys()

    # Now for the store part

    def store_state(self, client_id: Optional[str] = ""):
        self.store_keys()

    def store_keys(self):
        _entity = self.upstream_get("unit")
        logger.debug(f"[OIC_PS] Entity: {_entity.name}")
        logger.debug(f"[OIC_PS] Stored keys belonging to: {_entity.context.keyjar.owners()}")
        _keyjar = getattr(_entity, 'keyjar')
        if _keyjar:
            logger.debug(f"[OIC_PS] Other key owners: {_keyjar.owners()}")
        for entity_id in _entity.context.keyjar.owners():
            if entity_id == "" or entity_id == _entity.entity_id:
                jwks = _entity.context.keyjar.export_jwks(private=True, issuer_id=entity_id)
                if entity_id == "":
                    entity_id = "__"
            else:
                jwks = _entity.context.keyjar.export_jwks(issuer_id=entity_id)
            logger.debug(f"[OIC_PS] store entity_id: {entity_id}, jwks: {jwks}")
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
                logger.debug(f"[OIC_PS] No jwks for {entity_id}")

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

            logger.debug(f"[OIC_PS] Restored keys for these owners: {keyjar.owners()}")
