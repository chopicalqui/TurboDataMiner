# -*- coding: utf-8 -*-
"""
This module implements the base class functionalities for all analyzers, modifiers, and custom message GUIs.
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

import os
import json
import base64
import traceback
from threading import Lock
from javax.swing import JPanel
from java.awt import BorderLayout
from turbodataminer.exports import ExportedMethods
from turbodataminer.ui.core.scripting import IdePane
from turbodataminer.ui.core.scripting import ErrorDialog
from turbodataminer.model.scripting import ScriptInformation
from turbodataminer.model.scripting import PluginInformation


class IntelBaseConfiguration:
    """
    This class parses an API for reading an intel plugin's JSON configuration.
    """

    def __init__(self, configuration=None):
        """The JSON object that shall be loaded"""
        self.script_info = None
        self.code_changed = False
        self.activated = False
        if configuration:
            self.script_info = ScriptInformation.load_json(
                configuration["script_info"] if "script_info" in configuration else {})
            self.code_changed = configuration["code_changed"] if "code_changed" in configuration else False
            self.activated = configuration["activated"] if "activated" in configuration else False


class IntelBase(JPanel):
    """
    This abstract class is the base class for all analyzers, modifiers, and custom message panes GUIs.
    """

    SCRIPTS_DIR = "scripts"

    def __init__(self, extender, plugin_id, plugin_category_id, pre_code=None, post_code=None, configuration=None,
                 executable_on_startup=False, closable_tabbed_pane=None, disable_start_stop_button=False,
                 disable_clear_session_button=False):
        """
        :param extender:
        :param id: Usually the class name. This information is used for storing the current state in Burp Suite in case
        the extension is unloaded.
        :param plugin_id: Is of type tubodataminer.model.scripting.PluginType and specifies the plugin type.
        :param plugin_category_id: Is of type tubodataminer.model.scripting.PluginCategory and specifies the plugin
        category.
        :param pre_code: If specified, then this code is inserted before the user-provided script code.
        :param pre_code: If specified, then this code is appended to the user-provided script code.
        :param configuration: JSON object containing configuration information for the given plugin type. Usually
        this configuration is obtained from Burp Suite's configuration storage at startup.
        :param executable_on_startup: Boolean that specifies whether the given plugin type is allowed (True) to
        automatically execute after startup.
        :closable_tabbed_pane: Is of type JTabbedPaneClosable and allows the intelligence plugin to access content of
        the tabbed pane like the current tab's title.
        """
        JPanel.__init__(self)
        self.setLayout(BorderLayout())
        self._extender = extender
        self._callbacks = extender.callbacks
        self._plugin_category_id = plugin_category_id
        self._helpers = self._callbacks.getHelpers()
        self._plugin_id = plugin_id
        self._scripts_dir = os.path.join(extender.home_dir, IntelBase.SCRIPTS_DIR)
        self._ide_pane = IdePane(self,
                                 pre_script_code=pre_code,
                                 post_script_code=post_code,
                                 disable_start_stop_button=disable_start_stop_button,
                                 disable_clear_session_button=disable_clear_session_button)
        self._exported_methods = ExportedMethods(extender, self._ide_pane)
        self._session = {}
        self._ref = 1
        self._executable_on_startup = executable_on_startup
        self._ide_pane.code_changed = False
        self.closable_tabbed_pane = closable_tabbed_pane
        # Load configuration
        if not configuration:
            configuration = IntelBaseConfiguration()
            configuration.script_info = ScriptInformation(plugins=[PluginInformation.get_plugin_by_id(self._plugin_id)])
        configuration.activated = configuration.activated and executable_on_startup
        self._ide_pane.script_info = configuration.script_info
        self._ide_pane.code_changed = configuration.code_changed
        # Register start, stop and cleaning methods
        self._ide_pane.register_start_analysis_function(self.start_analysis)
        self._ide_pane.register_stop_analysis_function(self.stop_analysis)
        self._ide_pane.register_clear_session_function(self.clear_session)

    @property
    def ide_pane(self):
        return self._ide_pane

    @property
    def extender(self):
        return self._extender

    @property
    def callbacks(self):
        return self._callbacks

    @property
    def plugin_category_id(self):
        return self._plugin_category_id

    @property
    def plugin_id(self):
        return self._plugin_id

    @property
    def scripts_dir(self):
        return self._scripts_dir

    @property
    def session(self):
        return self._session

    def get_json(self):
        result = {}
        script_info = self._ide_pane.script_info
        result["script_info"] = script_info.get_json()
        result["code_changed"] = self._ide_pane.code_changed
        result["activated"] = self._ide_pane.activated
        return result

    def clear_session(self):
        with self._table_model_lock:
            self._session = {}

    def start_analysis(self):
        """This method is invoked when the analysis is started"""
        raise NotImplementedError("This function is not implemented!")

    def stop_analysis(self):
        """This method is invoked when the analysis is stopped"""
        pass

    def process_proxy_history_entry(self, message_info, is_request=False, tool_flag=None, send_date=None, received_date=None,
                                    listener_interface=None, client_ip_address=None, timedout=None,
                                    message_reference=None, proxy_message_info=None, time_delta=None, in_scope=None,
                                    communication_manager=None, invocation=None):
        raise NotImplementedError("Method not implemented yet")
