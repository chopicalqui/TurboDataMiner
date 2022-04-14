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
from burp import IMessageEditorTabFactory
from turbodataminer.model.scripting import PluginType
from turbodataminer.model.scripting import PluginCategory
from turbodataminer.ui.core.intelbase import IntelBase
from turbodataminer.ui.core.scripting import ErrorDialog


class CustomMessageEditorTabBase(IntelBase):
    """
    This class implements the GUI and base class for on the fly modifications.
    """

    def __init__(self, pre_code=None, post_code=None, **kwargs):
        IntelBase.__init__(self,
                           plugin_category_id=PluginCategory.custom_message_editor,
                           pre_code=pre_code,
                           post_code=post_code,
                           **kwargs)


class CustomMessageEditorBase(IMessageEditorTab):
    """
    This class implements the base functionalities for the custom editors
    """

    def __init__(self, custom_editor_tab, controller, editable):
        """
        Initializes the IMessageEditorTab instance. This constructor is called by
        CustomMessageEditorTab.createNewInstance
        :param custom_editor_tab: The CustomMessageEditorTab that is displayed in the Others tab. This
        object provides access to all necessary information like extender.
        :param controller: Provided by IMessageEditorTabFactory
        :param editable: Provided by IMessageEditorTabFactory
        """
        self._custom_editor_tab = custom_editor_tab
        self._extender = custom_editor_tab.extender
        self._controller = controller
        self._editable = editable
        self._current_message = None

    def isEnabled(self, content, is_request):
        rvalue = False
        try:
            if self._custom_editor_tab.is_enabled:
                rvalue = self._custom_editor_tab.is_enabled(content,
                                                            is_request,
                                                            self._custom_editor_tab.session)
        except:
            self._custom_editor_tab.ide_pane.activated = False
            self._custom_editor_tab.stop_analysis()
            traceback.print_exc(file=self._extender.callbacks.getStderr())
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
            self._custom_editor_tab.ide_pane.activated = False
            self._custom_editor_tab.stop_analysis()
            traceback.print_exc(file=self._extender.callbacks.getStderr())
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
            self._custom_editor_tab.ide_pane.activated = False
            self._custom_editor_tab.stop_analysis()
            traceback.print_exc(file=self._extender.callbacks.getStderr())
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

    def __init__(self, editable, **kwargs):
        CustomMessageEditorBase.__init__(self, editable=editable, **kwargs)
        # create an instance of Burp Suite's text editor, to display our deserialized data
        self._text_editor = self._extender.callbacks.createTextEditor()
        self._text_editor.setEditable(editable)

    def getTabCaption(self):
        result = "Turbo Miner"
        try:
            closable_tabbed_pane = self._custom_editor_tab.closable_tabbed_pane
            if closable_tabbed_pane:
                tab_index = closable_tabbed_pane.indexOfComponent(self._custom_editor_tab)
                if tab_index >= 0:
                    tab_component = closable_tabbed_pane.getTabComponentAt(tab_index)
                    result = tab_component.get_title()
        except:
            traceback.print_exc(file=self._extender.callbacks.getStdout())
        return result

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


class CustomMessageEditorTab(CustomMessageEditorTabBase, IMessageEditorTabFactory):
    """
    This class is used by the CustomTextEditorImplementation class. It implements the logic to write, compile, and
    integrate the code into Burp Suite's message editor tab.
    """

    POST_CODE = """_set_message = set_message
_get_message = get_message
_is_enabled = is_enabled"""

    def __init__(self, **kwargs):
        CustomMessageEditorTabBase.__init__(self,
                                            executable_on_startup=True,
                                            plugin_id=PluginType.custom_message_editor,
                                            post_code=CustomMessageEditorTab.POST_CODE,
                                            **kwargs)
        self._is_enabled_lock = Lock()
        self._is_enabled = None
        self._set_message_lock = Lock()
        self._set_message = None
        self._get_message_lock = Lock()
        self._get_message = None
        self._session_lock = Lock()
        self._session = {}
        self.add(self._ide_pane)

    def start_analysis(self):
        try:
            # Setup API
            self.session = {}
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
                'find_error_messages': self._exported_methods.find_error_messages,
                'get_extension_info': self._exported_methods.get_extension_info,
                'decode_html': self._exported_methods.decode_html,
                'url_decode': self._exported_methods.url_decode,
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
                'has_stopped': self._exported_methods.has_stopped,
                '_set_message': self._set_message,
                '_get_message': self._get_message,
                '_is_enabled': self._is_enabled,
                'helpers': self._helpers
            }
            # Execute script
            exec(self.ide_pane.compiled_code, globals)
            # Reimport API method implementations
            self.set_message = globals['_set_message']
            self.get_message = globals['_get_message']
            self.is_enabled = globals['_is_enabled']
            # Register IMessageEditorTabFactory
            self._extender.callbacks.registerMessageEditorTabFactory(self)
        except:
            self._ide_pane.activated = False
            self.stop_analysis()
            traceback.print_exc(file=self._extender.callbacks.getStdout())
            ErrorDialog.Show(self._extender.parent, traceback.format_exc())

    def stop_analysis(self):
        # Unregister IMessageEditorTabFactory
        self._extender.callbacks.removeMessageEditorTabFactory(self)
        # Delete current method definition
        self.set_message = None
        self.get_message = None
        self.is_enabled = None
        self.session = {}

    @property
    def is_enabled(self):
        with self._is_enabled_lock:
            result = self._is_enabled
        return result

    @is_enabled.setter
    def is_enabled(self, value):
        with self._is_enabled_lock:
            self._is_enabled = value

    @property
    def set_message(self):
        with self._set_message_lock:
            result = self._set_message
        return result

    @set_message.setter
    def set_message(self, value):
        with self._set_message_lock:
            self._set_message = value

    @property
    def get_message(self):
        with self._get_message_lock:
            result = self._get_message
        return result

    @get_message.setter
    def get_message(self, value):
        with self._get_message_lock:
            self._get_message = value

    @property
    def session(self):
        with self._session_lock:
            result = self._session
        return result

    @session.setter
    def session(self, value):
        with self._session_lock:
            self._session = value

    def createNewInstance(self, controller, editable):
        """This method implements IMessageEditorTabFactory.createNewInstance"""
        return CustomTextEditorImplementation(custom_editor_tab=self, controller=controller, editable=editable)

    def process_proxy_history_entry(self, message_info, is_request=False, tool_flag=None, send_date=None,
                                    received_date=None, listener_interface=None, client_ip_address=None,
                                    timedout=None, message_reference=None, proxy_message_info=None, time_delta=None,
                                    in_scope=None, communication_manager=None, invocation=None):
        pass
