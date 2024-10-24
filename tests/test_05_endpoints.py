import os

from idpyoidc.util import load_yaml_config

from satosa_idpyop.core.application import idpy_oidc_application
from satosa_idpyop.endpoints import IdpyOPEndpoints

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


def test():
    frontend_config = load_yaml_config(full_path("satosa_conf.yaml"))
    _cnf = frontend_config["op"]["server_info"]["entity_type"]["openid_provider"]["kwargs"]["config"]
    _user_db_file = _cnf["userinfo"]["kwargs"]["db_file"]
    _cnf["userinfo"]["kwargs"]["db_file"] = full_path(_user_db_file)

    app = idpy_oidc_application(frontend_config)
    endpoints = IdpyOPEndpoints(app, None, {})
    assert endpoints
    assert getattr(endpoints, "authorization_endpoint")
    assert getattr(endpoints, "jwks_endpoint")
    assert getattr(endpoints, "entity_configuration_endpoint")
