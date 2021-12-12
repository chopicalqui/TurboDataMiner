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
from burp import IExtensionStateListener
from turbodataminer.exports import ExportedMethods
from turbodataminer.ui.core.scripting import IdePane
from turbodataminer.ui.core.scripting import ErrorDialog
from turbodataminer.model.scripting import ScriptInformation


class IntelBase(JPanel, IExtensionStateListener):
    """
    This abstract class is the base class for all analyzers, modifiers, and custom message panes GUIs.
    """

    INSTANCE_COUNT = 1
    SCRIPTS_DIR = "scripts"

    def __init__(self, extender, id, plugin_id, plugin_category_id, pre_code=None, post_code=None):
        """
        :param extender:
        :param id: Usually the class name. This information is used for storing the current state in Burp Suite in case
        the extension is unloaded.
        :param plugin_id:
        :param script_dir: The file system directory where the scripts are stored
        """
        JPanel.__init__(self)
        self._id = "{}:{:03d}".format(id, IntelBase.INSTANCE_COUNT)
        IntelBase.INSTANCE_COUNT = IntelBase.INSTANCE_COUNT + 1
        self.setLayout(BorderLayout())
        self._extender = extender
        self._callbacks = extender.callbacks
        self._plugin_category_id = plugin_category_id
        self._helpers = self._callbacks.getHelpers()
        self._plugin_id = plugin_id
        self._scripts_dir = os.path.join(extender.home_dir, IntelBase.SCRIPTS_DIR)
        self._ide_pane = IdePane(self, pre_code, post_code)
        self._exported_methods = ExportedMethods(extender, self._ide_pane)
        self._session = {}
        self._ref_lock = Lock()
        self._ref = 1
        self._ide_pane.code_changed = False
        # load configuration
        try:
            json_object = self._callbacks.loadExtensionSetting("{}_code".format(self._id))
            if json_object:
                json_object = base64.b64decode(json_object)
                json_object = json.JSONDecoder().decode(json_object)
                self._ide_pane.script_info = ScriptInformation.load_json(json_object)
                if "code_changed" in json_object:
                    self._ide_pane.code_changed = json_object["code_changed"]
                else:
                    self._ide_pane.code_changed = False
        except:
            traceback.print_exc(file=self._callbacks.getStderr())
            ErrorDialog.Show(self._extender.parent, traceback.format_exc())
            self._ide_pane.script_info = ScriptInformation(plugins=[PluginInformation.get_plugin_by_id(self._plugin_id)])
        self._callbacks.registerExtensionStateListener(self)
        self._ide_pane.register_start_analysis_function(self.start_analysis)
        self._ide_pane.register_stop_analysis_function(self.stop_analysis)
        self._ide_pane.register_clear_session_function(self.clear_session)

    @property
    def id(self):
        return self.id

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

    def extensionUnloaded(self):
        """This method is called when the extension is unloaded."""
        try:
            self._ide_pane.activated = False
            script_info = self._ide_pane.script_info
            b64_script_info = script_info.get_json()
            b64_script_info["code_changed"] = self._ide_pane.code_changed
            b64_script_info = json.JSONEncoder().encode(b64_script_info)
            b64_script_info = base64.b64encode(b64_script_info)
            self._callbacks.saveExtensionSetting("{}_code".format(self._id), b64_script_info)
        except:
            traceback.print_exc(file=self._callbacks.getStderr())
            ErrorDialog.Show(self._extender.parent, traceback.format_exc())

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
                                    message_reference=None, proxy_message_info=None, time_delta=None, in_scope=None):
        raise NotImplementedError("Method not implemented yet")
