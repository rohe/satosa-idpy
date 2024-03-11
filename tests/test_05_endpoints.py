from idpyoidc.util import load_yaml_config
from satosa_idpyop.core.application import idpy_oidc_application
from satosa_idpyop.endpoints import IdpyOPEndpoints


def test():
    frontend_config = load_yaml_config("satosa_conf.yaml")
    app = idpy_oidc_application(frontend_config)
    endpoints = IdpyOPEndpoints(app, None, {})
    assert endpoints
    assert getattr(endpoints, "authorization_endpoint")
    assert getattr(endpoints, "jwks_endpoint")
    assert getattr(endpoints, "entity_configuration_endpoint")
