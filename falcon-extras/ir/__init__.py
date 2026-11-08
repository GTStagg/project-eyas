"""Incident-response helper modules for the falcon-extras sidecar.

The agentic IR workflow's load-bearing logic lives here so it can be unit-
tested in isolation from FalconPy / MCP plumbing. Tools registered in
``server.py`` are thin wrappers that delegate to these modules.
"""
