class FakeDns:
    """In-memory DNS so tests never touch the network."""

    def __init__(self, txt=None, mx=None, exists=True):
        self._txt = {k.lower(): v for k, v in (txt or {}).items()}
        self._mx = {k.lower(): v for k, v in (mx or {}).items()}
        self._exists = exists

    def txt(self, name):
        return list(self._txt.get(name.lower(), []))

    def mx(self, name):
        return list(self._mx.get(name.lower(), []))

    def exists(self, name):
        return self._exists
