"""Vendor adapter contract. A vendor package supplies collection commands,
parsers and rules; core/ stays vendor-neutral. Read-only by default."""
class VendorAdapter:
    name = 'base'
    status = 'stub'            # 'ready' or 'stub'
    commands = []              # read-only commands to run
    def detect(self, text):    # -> bool
        return False
    def parse(self, outputs):  # -> dict (hostname, platform, ifaces, ...)
        raise NotImplementedError
    def checks(self, cfg):     # -> list of check dicts (id, title, weight, score, detail)
        raise NotImplementedError
