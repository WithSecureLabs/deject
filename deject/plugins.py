# plugins.py
"""!
@brief This file is used to run plugin files, from the "scripts" folder.
"""
from typing import Any, Dict
from pathlib import Path
import functools
import importlib
from collections import namedtuple
from importlib import resources


class Deject:
    def __init__(self) -> None:
        """Blocks direct instantiation of a class object instance.

        Deject is designed as a 'singleton', the run command sets up the class attributes via the create method,
        import Deject in a plugin will give a plugin access to those attributes.
        """
        raise TypeError("singleton class")
    file_path: Any
    r2_handler: Any
    quiet: bool
    plugin_args: Any

    @classmethod
    def create(cls, memory_dump: Path, quiet: bool = False, plugin_args: Any = False, r2: Any = None):
        """Modify the state of the Deject class instance.

        Used by the Deject run command.
        """
        cls.file_path = str(memory_dump)
        cls.r2_handler = r2
        cls.quiet = quiet
        cls.plugin_args = plugin_args
        return cls

    @staticmethod
    def plugin(func):
        """Decorator for registering a new plugin to the Deject application.

        Attached to Deject class so it's also imported with Deject to save a separate import and keep
        the overhead for writing a compatible plugin to the minimum.
        """
        package, _, plugin = func.__module__.rpartition(".")
        pkg_info = _PLUGINS.setdefault(package, {})
        pkg_info[plugin] = Plugin(name=plugin, func=func)
        return func


# Functions for dynamic loading of plugins from scripts folder
# also utilises the /scripts/__init__.py to work
Plugin = namedtuple("Plugin", ("name", "func"))
_PLUGINS: Dict[str, Any] = {}


def names(package):
    """List all plugins in one package"""
    _import_all(package)
    return sorted(_PLUGINS[package])


def get(package, plugin):
    """Get a given plugin"""
    _import(package, plugin)
    return _PLUGINS[package][plugin].func


def call(package, plugin, *args, **kwargs):
    """Call the given plugin"""
    plugin_func = get(package, plugin)
    return plugin_func(*args, **kwargs)


def doc(package, plugin):
    """Call the given plugin"""
    plugin_func = get(package, plugin)
    return plugin_func.__doc__


def _import(package, plugin):
    """Import the given plugin file from a package"""
    importlib.import_module(f"{package}.{plugin}")


def _import_all(package):
    """Import all plugins in a package"""
    files = (resource.name for resource in resources.files(package).iterdir() if resource.is_file())
    plugins = [f[:-3] for f in files if f.endswith(".py") and f[0] != "_"]
    for plugin in plugins:
        _import(package, plugin)


def names_factory(package):
    """Create a names() function for one package"""
    return functools.partial(names, package)


def get_factory(package):
    """Create a get() function for one package"""
    return functools.partial(get, package)


def call_factory(package):
    """Create a call() function for one package"""
    return functools.partial(call, package)


def doc_factory(package):
    """Create __doc__ function for one package"""
    return functools.partial(doc, package)
