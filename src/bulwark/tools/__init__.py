"""bulwark.tools — bench + false-positive harnesses (ADR-050).

Previously shipped as the top-level `bulwark_bench` and `bulwark_falsepos`
packages. Collapsed into `bulwark.tools.{bench, falsepos}` in v2.5.13;
the old import paths are still re-exported via back-compat shims for
v2.5.x and will be removed in v3.
"""
