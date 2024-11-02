class Persistence(object):
    name = ""

    def __init__(self, storage, upstream_get):
        self.storage = storage
        self.upstream_get = upstream_get
