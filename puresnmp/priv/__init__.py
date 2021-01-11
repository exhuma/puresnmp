import importlib
import pkgutil

import puresnmp.priv

#: Global registry of detected plugins
DISCOVERED_PLUGINS = {}


def iter_namespace(ns_pkg):
    # Specifying the second argument (prefix) to iter_modules makes the
    # returned name an absolute name instead of a relative one. This allows
    # import_module to work without having to do additional modification to
    # the name.
    return pkgutil.iter_modules(ns_pkg.__path__, ns_pkg.__name__ + ".")


def discover_plugins():
    for _, name, _ in iter_namespace(puresnmp.priv):
        mod = importlib.import_module(name)
        if not all(
            [
                hasattr(mod, "encrypt_data"),
                hasattr(mod, "decrypt_data"),
                hasattr(mod, "IDENTIFIER"),
            ]
        ):
            continue
        if mod.IDENTIFIER in DISCOVERED_PLUGINS:
            raise ImportError(
                "Plugin %r causes a name-clash with the identifier %r. This is already used by %r"
                % (mod, mod.IDENTIFIER, DISCOVERED_PLUGINS[mod.IDENTIFIER])
            )
        DISCOVERED_PLUGINS[mod.IDENTIFIER] = mod


class Priv:
    @staticmethod
    def create(name: str) -> "Priv":

        if not DISCOVERED_PLUGINS:
            discover_plugins()
        return DISCOVERED_PLUGINS[name]
