from vendors.base import VendorAdapter
from vendors.cisco import Cisco
def _stub(n):
    return type(n.title(), (VendorAdapter,), {'name': n})
ADAPTERS = [Cisco()] + [_stub(n)() for n in ('mikrotik', 'juniper', 'fortinet', 'aruba', 'hpe')]
def get(name):
    return next((a for a in ADAPTERS if a.name == name), None)
def detect(text):
    return next((a for a in ADAPTERS if a.status == 'ready' and a.detect(text)), None)
