"""
Test the plugin architecture for modular components
"""

from unittest.mock import MagicMock, patch

import puresnmp.plugins.pluginbase as base


@patch("puresnmp.plugins.pluginbase.importlib")
@patch("puresnmp.plugins.pluginbase.iter_namespace")
def test_base_broken_namespace(iter_namespace, importlib):
    """
    We don't want to crash out on broken namespaces
    """
    validity_checker = MagicMock()
    importlib.import_module.side_effect = ImportError("yoinks")
    result = base.discover_plugins("my.namespace", validity_checker)
    # TODO: check logging
    assert result == {}


@patch("puresnmp.plugins.pluginbase.importlib")
@patch("puresnmp.plugins.pluginbase.iter_namespace")
def test_broken_plugin(iter_namespace, importlib):
    validity_checker = MagicMock()
    validity_checker.return_value = True
    fake_plugin = MagicMock()
    fake_plugin.IDENTIFIER = "fake-plugin"
    fake_ns = object()
    importlib.import_module.side_effect = [fake_ns, ImportError("yoinks")]
    iter_namespace.return_value = [(-1, "pluginname", -1)]
    result = base.discover_plugins("my.namespace", validity_checker)
    # TODO: check logging
    assert result == {}


@patch("puresnmp.plugins.pluginbase.importlib")
@patch("puresnmp.plugins.pluginbase.iter_namespace")
def test_load_plugin(iter_namespace, importlib):
    validity_checker = MagicMock()
    validity_checker.return_value = True
    fake_plugin = MagicMock()
    fake_plugin.IDENTIFIER = "fake-plugin"
    fake_ns = object()
    importlib.import_module.side_effect = [fake_ns, fake_plugin]
    iter_namespace.return_value = [(-1, "pluginname", -1)]
    result = base.discover_plugins("my.namespace", validity_checker)
    iter_namespace.assert_called_with(fake_ns)
    assert result == {"fake-plugin": fake_plugin}


@patch("puresnmp.plugins.pluginbase.importlib")
@patch("puresnmp.plugins.pluginbase.iter_namespace")
def test_skip_invalid_module(iter_namespace, importlib):
    validity_checker = MagicMock()
    validity_checker.return_value = False
    fake_plugin = MagicMock()
    fake_plugin.IDENTIFIER = "fake-plugin"
    fake_ns = object()
    importlib.import_module.side_effect = [fake_ns, fake_plugin]
    iter_namespace.return_value = [(-1, "pluginname", -1)]
    result = base.discover_plugins("my.namespace", validity_checker)
    iter_namespace.assert_called_with(fake_ns)
    assert result == {}


@patch("puresnmp.plugins.pluginbase.discover_plugins")
def test_loader(discover_plugins):
    fake_module = MagicMock()
    discover_plugins.return_value = {"plugname": fake_module}
    validity_checker = MagicMock(return_value=True)
    loader = base.Loader("fake-namespace", validity_checker)
    mod = loader.create("plugname")
    assert mod == fake_module


@patch("puresnmp.plugins.pluginbase.discover_plugins")
def test_load_nonexisting(discover_plugins):
    fake_module = MagicMock()
    discover_plugins.return_value = {"plugname": fake_module}
    validity_checker = MagicMock(return_value=True)
    loader = base.Loader("fake-namespace", validity_checker)
    mod = loader.create("non-existend-name")
    assert mod is None
