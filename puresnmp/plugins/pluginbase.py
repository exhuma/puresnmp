import importlib
import logging
from threading import Lock
from types import ModuleType
from typing import Any, Callable, Dict

from puresnmp.util import iter_namespace

DISCOVERY_LOCK = Lock()
LOG = logging.getLogger(__name__)


def discover_plugins(
    namespace: str, is_valid_module: Callable[[ModuleType], bool]
) -> Dict[Any, ModuleType]:
    """
    Load all plugins in the given namespace (only if it is a valid module)

    Module validity check is handed off to the *is_valid_module* callable.
    Any module that is not valid is silently skipped.
    """
    with DISCOVERY_LOCK:
        output: Dict[Any, ModuleType] = {}
        try:
            nsmod = importlib.import_module(namespace)
        except ImportError as exc:
            LOG.debug(
                "Unable to load plugins in %r: %s",
                namespace,
                exc,
                exc_info=True,
            )
            return {}

        for _, name, _ in iter_namespace(nsmod):
            try:
                mod = importlib.import_module(name)
            except ImportError as exc:
                LOG.debug(
                    "Unable to load plugin %r: %s", name, exc, exc_info=True
                )
                continue
            if not is_valid_module(mod):
                continue
            if mod.IDENTIFIER in output:  # type: ignore
                raise ImportError(
                    "Plugin %r causes a name-clash with the identifier %r. "
                    "This is already used by %r"
                    % (mod, mod.IDENTIFIER, output[mod.IDENTIFIER])  # type: ignore
                )
            output[mod.IDENTIFIER] = mod  # type: ignore

        return output


class Loader:
    def __init__(
        self, namespace: str, validator: Callable[[ModuleType], bool]
    ) -> None:
        self.namespace = namespace
        self.validator = validator
        self.discovered_plugins: Dict[Any, ModuleType] = {}

    def create(self, name: Any) -> Any:
        """
        Return an instance of the given privacy module by identifier.

        This looks up the module by "IDENTIFIER" as specified in the given plugin.

        If no plugin with the given identifier is found, a *KeyError* is raised
        """

        if not self.discovered_plugins:
            self.discovered_plugins = discover_plugins(
                self.namespace, self.validator
            )
        if name not in self.discovered_plugins:
            return None
        return self.discovered_plugins[name]
