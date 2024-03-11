from typing import List
from typing import Optional

from fedservice.utils import make_federation_entity
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS


def main(entity_id: str,
         authority_hints: Optional[List[str]] = None,
         trust_anchors: Optional[dict] = None,
         preference: Optional[dict] = None):
    intermediate = make_federation_entity(
        entity_id,
        key_config={"key_defs": DEFAULT_KEY_DEFS},
        trust_anchors=trust_anchors,
        authority_hints=authority_hints,
        preference=preference
    )

    return intermediate
