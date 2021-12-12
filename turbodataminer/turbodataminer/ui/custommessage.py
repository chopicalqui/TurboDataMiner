# -*- coding: utf-8 -*-
"""
This module implements all functionalities for all custom message GUIs.
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

import traceback
from threading import Lock
from burp import IMessageEditorTab
from turbodataminer.model.scripting import PluginType
from turbodataminer.model.scripting import PluginCategory
from turbodataminer.ui.core.intelbase import IntelBase
from turbodataminer.ui.core.scripting import ErrorDialog


class CustomMessageEditorTabBase(IntelBase):
    """
    This class implements the GUI and base class for on the fly modifications.
    """

    def __init__(self, extender, id, plugin_id, pre_code=None, post_code=None):
        IntelBase.__init__(self, extender, id, plugin_id, PluginCategory.custom_message_editor,
                           pre_code, post_code)


class CustomMessageEditorBase(IMessageEditorTab):
    """
    This class implements the base functionalities for the custom editors
    """

    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._editable = editable
        self._custom_editor_tab = extender.custom_editor_tab
        self._current_message = None

    def isEnabled(self, content, is_request):
        rvalue = False
        try:
            if self._custom_editor_tab.is_enabled:
                rvalue = self._custom_editor_tab.is_enabled(content,
                                                            is_request,
                                                            self._custom_editor_tab.session)
        except:
            self._extender.callbacks.printError(traceback.format_exc())
            ErrorDialog.Show(self._extender.parent, traceback.format_exc())
        return rvalue

    def setMessage(self, content, is_request):
        try:
            if self._custom_editor_tab.set_message:
                self._current_message = self._custom_editor_tab.set_message(content,
                                                                            is_request,
                                                                            self._custom_editor_tab.session)
                self._set_message(self._current_message, is_request, self._editable)
            else:
                self._set_message("", is_request, False)
        except:
            self._extender.callbacks.printError(traceback.format_exc())
            ErrorDialog.Show(self._extender.parent, traceback.format_exc())
            # clear our display
            self._set_message("", is_request, False)

    def getMessage(self):
        try:
            if self._custom_editor_tab.get_message:
                text = self._get_message()
                return self._custom_editor_tab.get_message(text, self._custom_editor_tab.session)
            else:
                return None
        except:
            self._extender.callbacks.printError(traceback.format_exc())
            ErrorDialog.Show(self._extender.parent, traceback.format_exc())
            return None

    def getTabCaption(self):
        raise NotImplementedError("Not implemented yet!")

    def getUiComponent(self):
        raise NotImplementedError("Not implemented yet!")

    def _set_message(self, content, is_request, editable):
        raise NotImplementedError("Not implemented yet!")

    def _get_message(self):
        raise NotImplementedError("Not implemented yet!")

    def isModified(self):
        raise NotImplementedError("Not implemented yet!")

    def getSelectedData(self):
        raise NotImplementedError("Not implemented yet!")


class CustomTextEditorImplementation(CustomMessageEditorBase):
    """
    This class implements Burp Suite's interface IMessageEditorTab to add a custom text editor tab in the Burp Suite
    GUI. Internally, this class uses class CustomMessageEditorTab to allow the management of custom editors in the
    Turbo Data Miner extension.
    """
    def __init__(self, extender, controller, editable):
        CustomMessageEditorBase.__init__(self, extender, controller, editable)

        # create an instance of Burp Suite's text editor, to display our deserialized data
        self._text_editor = extender.callbacks.createTextEditor()
        self._text_editor.setEditable(editable)

    def getTabCaption(self):
        return "Turbo Miner"

    def getUiComponent(self):
        return self._text_editor.getComponent()

    def _set_message(self, content, is_request, editable):
        self._text_editor.setText(content)
        self._text_editor.setEditable(editable)

    def _get_message(self):
        return self._text_editor.getText()

    def isModified(self):
        return self._text_editor.isTextModified()

    def getSelectedData(self):
        return self._text_editor.getSelectedText()


class CustomMessageEditorTab(CustomMessageEditorTabBase):
    """
    This class is used by the CustomTextEditorImplementation class. It implements the logic to write, compile, and
    integrate the code into Burp Suite's message editor tab.
    """

    POST_CODE = """_set_message = set_message
_get_message = get_message
_is_enabled = is_enabled"""

    def __init__(self, extender):
        CustomMessageEditorTabBase.__init__(self, extender, CustomMessageEditorTab.__name__,
                                            PluginType.custom_message_editor,
                                            post_code=CustomMessageEditorTab.POST_CODE)
        self._extender = extender
        self._is_enabled = None
        self._set_message = None
        self._get_message = None
        self.add(self._ide_pane)
        self._lock = Lock()

    def start_analysis(self):
        try:
            # Setup API
            self._session = {}

            globals = {
                'callbacks': self._extender.callbacks,
                'xerceslib': self._extender.xerces_classloader,
                'plugin_id': self._plugin_id,
                'get_json_attributes': self._exported_methods.get_json_attributes,
                'get_json_attribute_by_path': self._exported_methods.get_json_attribute_by_path,
                'get_headers': self._exported_methods.get_headers,
                'get_parameters': self._exported_methods.get_parameters,
                'get_parameter_name': self._exported_methods.get_parameter_name,
                'get_header': self._exported_methods.get_header,
                'get_cookies': self._exported_methods.get_cookies,
                'get_cookie_attributes': self._exported_methods.get_cookie_attributes,
                'get_hostname': self._exported_methods.get_hostname,
                'compress_gzip': self._exported_methods.compress_gzip,
                'decompress_gzip': self._exported_methods.decompress_gzip,
                'get_content_length': self._exported_methods.get_content_length,
                'get_content_type': self._exported_methods.get_content_type,
                'analyze_signatures': self._exported_methods.analyze_signatures,
                'get_extension_info': self._exported_methods.get_extension_info,
                'decode_html': self._exported_methods.decode_html,
                'analyze_request': self._exported_methods.analyze_request,
                'analyze_response': self._exported_methods.analyze_response,
                'find_versions': self._exported_methods.find_versions,
                'find_domains': self._exported_methods.find_domains,
                'get_jwt': self._exported_methods.get_jwt,
                'decode_jwt': self._exported_methods.decode_jwt,
                'encode_jwt': self._exported_methods.encode_jwt,
                'send_http_message': self._exported_methods.send_http_message,
                'split_http_header': self._exported_methods.split_http_header,
                'has_header': self._exported_methods.has_header,
                '_set_message': self._set_message,
                '_get_message': self._get_message,
                '_is_enabled': self._is_enabled,
                'helpers': self._helpers
            }
            # Execute script
            exec(self.ide_pane.compiled_code, globals)
            # Reimport API method implementations
            with self._lock:
                self._set_message = globals['_set_message']
                self._get_message = globals['_get_message']
                self._is_enabled = globals['_is_enabled']
        except:
            traceback.print_exc(file=self._callbacks.getStderr())
            ErrorDialog.Show(self._extender.parent, traceback.format_exc())
            self._ide_pane.activated = False

    def stop_analysis(self):
        with self._lock:
            self._set_message = None
            self._get_message = None
            self._is_enabled = None
            self._tab_caption = None

    @property
    def is_enabled(self):
        with self._lock:
            return self._is_enabled

    @property
    def set_message(self):
        with self._lock:
            return self._set_message

    @property
    def get_message(self):
        with self._lock:
            return self._get_message

    @property
    def session(self):
        return self._session

    def process_proxy_history_entry(self, message_info, is_request=False, tool_flag=None, send_date=None,
                                received_date=None, listener_interface=None, client_ip_address=None,
                                timedout=None, message_reference=None, proxy_message_info=None, time_delta=None,
                                in_scope=None):
        pass
