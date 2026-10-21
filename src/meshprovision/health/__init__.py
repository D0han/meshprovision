"""Per-node health from lorastats packet reports: parsing, history, metrics and rules.

Read-only like ``mesh status``: nothing here writes the database or a
device. The only files written are the per-node history files in the
cache directory (see :mod:`meshprovision.health.history`).
"""
