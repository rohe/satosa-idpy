from typing import Optional

from idpyoidc.server import user_info

from satosa_idpyop.utils import combine_client_subject_id


class UserInfo(user_info.UserInfo):

    def load(self, info):
        self.db.update(info)


class ProxyUserInfo(object):

    def __init__(self, upstream_get, credential_type_to_claims: Optional[dict] = None):
        self.upstream_get = upstream_get
        self.credential_type_to_claims = credential_type_to_claims

    def __call__(self, user_id, client_id=None):
        _persistence = self.upstream_get("attribute", "persistence")
        client_subject_id = combine_client_subject_id(client_id, user_id)
        return _persistence.load_claims(client_subject_id)

class PassThruUserInfo(object):

    def __init__(self, upstream_get, attributes: Optional[list] = None):
        self.upstream_get = upstream_get
        self.attributes = attributes or []

    def __call__(self, user_id, client_id=None):
        _persistence = self.upstream_get("attribute", "persistence")
        client_subject_id = combine_client_subject_id(client_id, user_id)
        return _persistence.load_claims(client_subject_id)
