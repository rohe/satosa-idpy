from typing import List
from typing import Optional

from fedservice.defaults import LEAF_ENDPOINTS
from fedservice.utils import make_federation_combo
from idpyoidc.client.client_auth import CLIENT_AUTHN_METHOD
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS


def main(entity_id: str,
         authority_hints: Optional[List[str]],
         trust_anchors: Optional[dict],
         preference: Optional[dict] = None):

    _conf = {
        "client_type": "oidc",
        "keys": {"key_defs": DEFAULT_KEY_DEFS},
        "client_authn_methods": CLIENT_AUTHN_METHOD,
        "preference": {
            "response_types_supported": ["code"],
            "token_endpoint_auth_methods_supported": ["private_key_jwt"],
        },
        "add_ons": {
            "pushed_authorization": {
                "function": "idpyoidc.client.oauth2.add_on.par.add_support",
                "kwargs": {
                    "body_format": "jws",
                    "signing_algorithm": "RS256",
                    "http_client": None,
                    "merge_rule": "lax",
                },
            }
        },
        "redirect_uris": ["https://rp.example.com/authz_cb"],
        "userinfo_request_method": "GET",
        "services": {
            "discovery": {
                "class": "idpyoidc.client.oidc.provider_info_discovery.ProviderInfoDiscovery"
            },
            "authorization": {"class": "idpyoidc.client.oidc.authorization.Authorization"},
            "access_token": {"class": "idpyoidc.client.oidc.access_token.AccessToken"},
            "userinfo": {"class": "idpyoidc.client.oidc.userinfo.UserInfo"},
        }
    }
    _conf["client_id"] = entity_id

    rp = make_federation_combo(
        entity_id,
        preference=preference,
        authority_hints=authority_hints,
        key_config={"key_defs": DEFAULT_KEY_DEFS},
        endpoints=LEAF_ENDPOINTS,
        trust_anchors=trust_anchors,
        entity_type={
            "openid_relying_party": {
                'class': 'fedservice.appclient.ClientEntity',
                'kwargs': {
                    # "base_url": entity_id,
                    'config': _conf
                }
            }
        }
    )

    return rp
