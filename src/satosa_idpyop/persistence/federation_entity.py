import logging

from cryptojwt import KeyJar
from fedservice.entity_statement.cache import ESCache
from fedservice.entity_statement.statement import TrustChain
from idpyoidc.key_import import import_jwks

from satosa_idpyop.persistence import Persistence

logger = logging.getLogger(__name__)


# Doesn't know about ExtendedContext

class FEPersistence(Persistence):

    def __init__(self, storage, upstream_get):
        super(FEPersistence, self).__init__(storage, upstream_get)

    # Below, federation entity stuff
    def store_federation_cache(self):
        _entity = self.upstream_get("unit")
        _cache = _entity.function.trust_chain_collector.config_cache
        self.storage.store(information_type="entity_configuration", value=_cache.dump())
        _cache = _entity.function.trust_chain_collector.entity_statement_cache
        self.storage.store(information_type="entity_statement", value=_cache.dump())

    def restore_federation_cache(self):
        _entity = self.upstream_get("unit")
        _cache = ESCache()
        _info = self.storage.fetch(information_type="entity_configuration")
        if _info:
            _cache.load(_info)
        else:
            logger.debug("No Entity Configurations cached")
        _entity.function.trust_chain_collector.config_cache = _cache

        _cache = ESCache()
        _info = self.storage.fetch(information_type="entity_statement")
        if _info:
            _cache.load(_info)
        else:
            logger.debug("No Entity Statements cached")
        _entity.function.trust_chain_collector.entity_statement_cache = _cache

    def store_federation_keys(self):
        _entity = self.upstream_get("unit")
        for entity_id in _entity.keyjar.owners():
            if entity_id == "" or entity_id == _entity.entity_id:
                jwks = _entity.keyjar.export_jwks(private=True, issuer_id=entity_id)
                if entity_id == "":
                    entity_id = "__"
            else:
                jwks = _entity.keyjar.export_jwks(issuer_id=entity_id)
            self.storage.store(information_type="fed_jwks", key=entity_id, value=jwks)

    def restore_federation_keys(self):
        keyjar = KeyJar()
        for entity_id in self.storage.keys_by_information_type("fed_jwks"):
            jwks = self.storage.fetch(information_type="fed_jwks", key=entity_id)
            if jwks:
                if entity_id == '__':
                    entity_id = ""
                keyjar = import_jwks(keyjar, jwks, entity_id)
            else:
                logger.debug(f"No jwks for {entity_id}")
        _guise = self.upstream_get("unit")
        # For federation entities the keyjar is in the FederationEntity object
        _guise.keyjar = keyjar
        _httpc_params = getattr(_guise, "httpc_params", None)
        if _httpc_params:
            _guise.keyjar.httpc_params = _httpc_params

    def store_trust_chains(self):
        _entity = self.upstream_get("unit")
        if _entity.trust_chain:
            for leaf, chain in _entity.trust_chain.items():
                _chains = [tc.dump() for tc in chain]
                self.storage.store(information_type="trust_chain", value=_chains, key=leaf)

    def restore_trust_chains(self):
        for entity_id in self.storage.keys_by_information_type("trust_chain"):
            _chains = self.storage.fetch(information_type="trust_chain", key=entity_id)
            _entity = self.upstream_get("unit")
            _entity.store_trust_chains(entity_id, [TrustChain().load(v) for v in _chains])

    def reset_state(self):
        _entity = self.upstream_get("unit")
        _entity.trust_chain = {}
        _entity.keyjar = KeyJar()
        _entity.function.trust_chain_collector.config_cache = {}
        _entity.function.trust_chain_collector.entity_statement_cache = {}

    def store_state(self):
        self.store_trust_chains()
        self.store_federation_keys()
        self.store_federation_cache()

    def restore_state(self):
        self.restore_trust_chains()
        self.restore_federation_keys()
        self.restore_federation_cache()
