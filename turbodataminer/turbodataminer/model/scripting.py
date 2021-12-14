# -*- coding: utf-8 -*-
"""
This module implements the core functionality for scripts
"""

__author__ = "Lukas Reiter"
__license__ = "GPL v3.0"
__copyright__ = """Copyright 2020 Lukas Reiter

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
__version__ = 1.0

import uuid
import json


class PluginType:
    proxy_history_analyzer = 0
    http_listener_analyzer = 1
    proxy_listener_analyzer = 2
    http_listener_modifier = 3
    proxy_listener_modifier = 4
    custom_message_editor = 5
    site_map_analyzer = 6


class PluginCategory:
    analyzer = 0
    modifier = 1
    custom_message_editor = 2


class PluginInformation:
    """
    This plugin holds information about a specific plugin (e.g., Proxy History Parser)
    """

    def __init__(self, plugin_id, name, category, selected=False):
        self._plugin_id = plugin_id
        self._name = name
        self._selected = selected
        self._category = category

    @property
    def plugin_id(self):
        return self._plugin_id

    @property
    def name(self):
        return self._name

    @property
    def selected(self):
        return self._selected

    @property
    def category(self):
        return self._category

    @staticmethod
    def get_plugin_by_id(plugin_id):
        for plugin in LIST:
            if plugin.plugin_id == plugin_id:
                return plugin
        return None

    @staticmethod
    def get_plugins_by_category(categories=None):
        rvalues = []
        if not isinstance(categories, list):
            categories = [categories]
        if not categories:
            return LIST
        for plugin in LIST:
            if plugin.category in categories:
                rvalues.append(plugin)
        return rvalues

    def __repr__(self):
        return self._name


LIST = [PluginInformation(PluginType.proxy_history_analyzer, "Proxy History Analyzer", PluginCategory.analyzer),
        PluginInformation(PluginType.site_map_analyzer, "Site Map Analyzer", PluginCategory.analyzer),
        PluginInformation(PluginType.http_listener_analyzer, "HTTP Listener Analyzer", PluginCategory.analyzer),
        PluginInformation(PluginType.http_listener_modifier, "HTTP Listener Modifier", PluginCategory.modifier),
        PluginInformation(PluginType.proxy_listener_modifier, "Proxy Listener Modifier", PluginCategory.modifier),
        PluginInformation(PluginType.custom_message_editor, "Custom Message Editor", PluginCategory.custom_message_editor)]


class ScriptInformation:
    """
    This class holds all information and methods about a script
    """

    def __init__(self, guid=str(uuid.uuid4()), name=None, author=None, version=None, plugins=[], script=None):
        self._uuid = guid
        self._name = name
        self._author = author
        self._version = version
        self._plugins = plugins
        self._script = script if script is not None else ""

    @property
    def uuid(self):
        return self._uuid

    @uuid.setter
    def uuid(self, value):
        self._uuid = value

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def author(self):
        return self._author

    @author.setter
    def author(self, value):
        self._author = value

    @property
    def script(self):
        return self._script

    @script.setter
    def script(self, value):
        self._script = value

    @property
    def version(self):
        return self._version

    @version.setter
    def version(self, value):
        self._version = value

    @property
    def plugins(self):
        return self._plugins

    @plugins.setter
    def plugins(self, value):
        self._plugins = value

    @staticmethod
    def load_json(object):
        """This method parses the given json object and returns a class of type ScriptInformation"""
        json_object = json.JSONDecoder().decode(object) if isinstance(object, str) else object
        plugins = []
        if "plugins" in json_object:
            plugins = [PluginInformation.get_plugin_by_id(plugin_id) for plugin_id in json_object["plugins"]]
        return ScriptInformation(json_object["uuid"] if "uuid" in json_object else None,
                                 json_object["name"] if "name" in json_object else None,
                                 json_object["author"] if "author" in json_object else None,
                                 json_object["version"] if "version" in json_object else None,
                                 plugins,
                                 json_object["script"] if "script" in json_object else None)

    def get_json(self):
        """This method returns a json object representing the object"""
        return {"uuid": self._uuid,
                "name": self._name,
                "author": self._author,
                "version": self._version,
                "plugins": [item.plugin_id for item in self._plugins],
                "script": self._script if self._script else ""}

    def __repr__(self):
        if self._name:
            return "{} ({}) - {} - {} - {}".format(self._name, self._uuid, self._version, self._author, self._plugins)
        return ""
