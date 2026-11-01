"""Region-wide traffic from lorastats raw packets: parsing, a compact store, relay resolution.

Read-only towards the database and every device, like ``mesh health``.
The only files written are the region stores in the cache directory (see
:mod:`meshprovision.network.store`).
"""
