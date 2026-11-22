# Vendor roadmap
| Vendor | Status |
|---|---|
| Cisco IOS / IOS-XE | Ready (tested live on one Catalyst 2960X) |
| MikroTik, Juniper, Fortinet, Aruba, HPE | Planned (stub adapters in `vendors/`) |
Adding a vendor: subclass `VendorAdapter`, implement detect/parse/checks, register in `vendors/registry.py`.
