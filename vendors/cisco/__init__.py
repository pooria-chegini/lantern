from vendors.base import VendorAdapter
class Cisco(VendorAdapter):
    name = 'cisco'; status = 'ready'
    # Working engine lives in audit/ (collector, parsers, checks).
    def detect(self, text):
        return 'version' in text.lower() and ('ios' in text.lower() or 'cisco' in text.lower())
    def parse(self, outputs):
        from audit import parsers; return parsers
    def checks(self, cfg):
        from audit import checks; return checks.evaluate(cfg) if hasattr(checks, 'evaluate') else []
