from idpyoidc.server.oidc.authorization import Authorization
from satosa_idpyop.endpoint_wrapper import get_endpoint_wrapper


def test():
    endpoint = Authorization(None)
    ew = get_endpoint_wrapper(endpoint)
    assert ew