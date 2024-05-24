import logging
from typing import Optional

from satosa_idpyop.endpoint_wrapper import get_special_endpoint_wrapper

from satosa_idpyop.endpoint_wrapper import get_endpoint_wrapper

from .core import ExtendedContext
from .endpoint_wrapper.jwks import JWKSEndpointWrapper

try:
    from satosa.context import add_prompt_to_context
except ImportError:
    def add_prompt_to_context(*args, **kwargs):
        pass

logger = logging.getLogger(__name__)

IGNORED_HEADERS = ["cookie", "user-agent"]


class IdpyOPEndpoints(object):
    """Handles all the Entity endpoints"""

    def __init__(self, app, auth_req_callback_func, converter, endpoint_wrapper_path=""):
        self.app = app
        _etype = [v for k,v in list(app.server.items()) if k != "federation_entity"]
        # Assumes there is only one guise except for the federation_entity
        self.entity_type = _etype[0]
        kwargs = {"auth_req_callback_func": auth_req_callback_func, "converter":converter}
        for entity_type, item in app.server.items():
            if entity_type == "federation_entity":
                for k, endp in item.server.endpoint.items():
                    _endpoint_wrapper = get_endpoint_wrapper(endp)
                    setattr(self, f"{k}_endpoint", _endpoint_wrapper(self.unit_get, endp, **kwargs))
            else:
                for k, endp in item.endpoint.items():
                    _endpoint_wrapper =  get_special_endpoint_wrapper(endpoint_wrapper_path, endp.name)
                    if not _endpoint_wrapper:
                        _endpoint_wrapper = get_endpoint_wrapper(endp)

                    if _endpoint_wrapper:
                        setattr(self, f"{k}_endpoint", _endpoint_wrapper(self.unit_get, endp, **kwargs))

        # add jwks.json web path
        self.jwks_endpoint = JWKSEndpointWrapper(self.unit_get, None)

    def unit_get(self, what, *arg):
        _func = getattr(self, f"get_{what}", None)
        if _func:
            return _func(*arg)
        return None

    def get_unit(self, *args):
        return self

    def get_guise(self, entity_type: Optional[str] = "", *args):
        if not entity_type:
            entity_type = self.entity_type

        return self.app.server[entity_type]

    def get_attribute(self, attribute_name, *args):
        attr = getattr(self, attribute_name, None)
        return attr

    def get_federation_entity(self, *args):
        return self.app.federation_entity

    # def authorization_endpoint(self, context: ExtendedContext):
    #     """
    #     OAuth2 / OIDC Authorization endpoint
    #     Checks client_id and handles the authorization request
    #     """
    #     logger.debug("At the Authorization Endpoint")
    #     _entity_type = self.get_guise(self.entity_type)
    #     _entity_type.persistence.restore_pushed_authorization()
    #     _fed_entity = self.get_guise("federation_entity")
    #     _fed_entity.persistence.restore_state()
    #
    #     resp = self.endpoint_wrapper["authorization"](context)
    #
    #     _fed_entity.persistence.store_state()
    #
    #     return resp
