"""PrivateFirewall — control plane + intrusion dashboard on the OS firewall.

The modules in this directory use flat imports (``import server``) because the
frozen Windows exe bundles them top-level; the launcher puts this directory on
sys.path.  This package marker exists for tooling (version detection by the
QuickOpen deb/usi builders) and for ``python -m`` style imports in tests.
"""

__version__ = "1.0.12"
