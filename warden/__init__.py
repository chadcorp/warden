"""
Warden -- the trusted skill brain for open agents (reference implementation).

Phase 0 reference stack. Pure Python standard library only: this package
intentionally has ZERO third-party dependencies so it runs on any Python 3.8+
and "nothing leaves your box."

Modules
-------
canonical        Deterministic (canonical) JSON serialization for signing.
ed25519          Pure-Python Ed25519 (RFC 8032) -- real signatures, no deps.
content_address  SHA-256 content addressing of skill bundles (pin a hash).
manifest         Load + validate the capability manifest (deny-by-default).
scanner          OWASP-aligned intake scanner (5 threat classes + drift).
policy           Deny-by-default capability enforcement engine.
trust            Behavioral trust score (per version, time-aware).
translog         Append-only, hash-linked + Merkle transparency log.
sign / verify    Sign and verify a skill bundle (CLI-callable).
node             Reference local MCP node (stdio JSON-RPC) -- the magic moment.
cli              `warden` command dispatcher.

This is a SIGNAL, not a guarantee. See SECURITY.md.
"""

__version__ = "0.2.0"
__all__ = ["__version__"]
