from cryptojwt.utils import importer
from fedservice.entity import FederationEntity
from fedservice.entity.utils import get_federation_entity

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

RESPONSE_TYPES_SUPPORTED = [
    ["code"],
    ["id_token"],
    ["code", "id_token"]
]


def create_trust_chain_messages(leaf, *entity):
    where_and_what = {}

    if isinstance(leaf, str):
        pass
    else:
        _endpoint = get_federation_entity(leaf).server.get_endpoint('entity_configuration')
        where_and_what[_endpoint.full_path] = _endpoint.process_request({})["response"]

    for n in range(0, len(entity)):
        ent = entity[n]
        if isinstance(ent, FederationEntity):
            _entity = ent
        else:  # A Combo
            _entity = ent['federation_entity']

        _endpoint = _entity.server.get_endpoint('entity_configuration')

        where_and_what[_endpoint.full_path] = _endpoint.process_request({})["response"]

        _endpoint = _entity.server.get_endpoint('fetch')
        if n == 0:
            if isinstance(leaf, str):
                _sub = leaf
            else:
                _sub = leaf.entity_id
        else:
            _sub = entity[n - 1].entity_id
        _req = _endpoint.parse_request({'iss': ent.entity_id, 'sub': _sub})
        where_and_what[_endpoint.full_path] = _endpoint.process_request(_req)["response_msg"]

    return where_and_what


def create_trust_chain(leaf, *entity):
    chain = []

    if isinstance(leaf, str):
        pass
    else:
        _endpoint = get_federation_entity(leaf).server.get_endpoint('entity_configuration')
        chain.append(_endpoint.process_request({})["response"])

    for n in range(0, len(entity)):
        ent = entity[n]
        if isinstance(ent, FederationEntity):
            _entity = ent
        else:  # A Combo
            _entity = ent['federation_entity']

        _endpoint = _entity.server.get_endpoint('entity_configuration')

        # chain.append(_endpoint.process_request({})["response"])

        _endpoint = _entity.server.get_endpoint('fetch')
        if n == 0:
            if isinstance(leaf, str):
                _sub = leaf
            else:
                _sub = leaf.entity_id
        else:
            _sub = entity[n - 1].entity_id
        _req = _endpoint.parse_request({'iss': ent.entity_id, 'sub': _sub})
        chain.append(_endpoint.process_request(_req)["response"])

    return chain


def execute_function(function, **kwargs):
    if isinstance(function, str):
        return importer(function)(**kwargs)
    else:
        return function(**kwargs)

TA_ID = "https://ta.example.org"
INT_ID = "https://intermediate.example.org"
RP_ID = "https://rp.example.org"

def federation_setup():

    entity = {}

    ##################
    # TRUST ANCHOR
    ##################

    kwargs = {
        "entity_id": TA_ID,
        "preference": {
            "organization_name": "The example federation operator",
            "homepage_uri": "https://ta.example.org",
            "contacts": "operations@ta.example.com"
        }
    }
    trust_anchor = execute_function('entities.ta.main', **kwargs)
    trust_anchors = {TA_ID: trust_anchor.keyjar.export_jwks()}
    entity["trust_anchor"] = trust_anchor

    ########################################
    # Intermediate
    ########################################

    kwargs = {
        "entity_id": INT_ID,
        "preference": {
            "organization_name": "An intermediate",
            "homepage_uri": "https://intermediate.example.com",
            "contacts": "operations@intermediate.example.com"
        },
        "authority_hints": [TA_ID],
        "trust_anchors": trust_anchors
    }
    intermediate = execute_function("entities.intermediate.main", **kwargs)

    trust_anchor.server.subordinate[INT_ID] = {
        "jwks": intermediate.keyjar.export_jwks(),
        'authority_hints': [TA_ID],
        "registration_info": {"entity_types": ["federation_entity"]},
    }
    entity["Intermediate"] = intermediate


    #########################################
    # Relying Party
    #########################################


    kwargs = {
        "entity_id": RP_ID,
        "preference": {
            "organization_name": "The OpenID RP",
            "homepage_uri": "https://rp.example.com",
            "contacts": "operations@rp.example.com"
        },
        "authority_hints": [TA_ID],
        "trust_anchors": trust_anchors
    }

    rp = execute_function("entities.rp.main", **kwargs)

    trust_anchor.server.subordinate[RP_ID] = {
        "jwks": rp['federation_entity'].keyjar.export_jwks(),
        'authority_hints': [TA_ID],
        "registration_info": {"entity_types": ["federation_entity", "openid_relying_party"]},
    }
    entity["relying_party"] = rp

    return entity


