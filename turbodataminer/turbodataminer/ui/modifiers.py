# -*- coding: utf-8 -*-
"""
This module implements all functionalities for all modifier GUIs.
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
from burp import IHttpListener
from burp import IProxyListener
from turbodataminer.ui.core.intelbase import IntelBase
from turbodataminer.ui.core.scripting import ErrorDialog
from turbodataminer.model.scripting import PluginType
from turbodataminer.model.scripting import PluginCategory


class ModifierTab(IntelBase):
    """
    This class implements the GUI and base class for on the fly modifications.
    """

    def __init__(self, **kwargs):
        IntelBase.__init__(self, plugin_category_id=PluginCategory.modifier, executable_on_startup=True, **kwargs)

    def start_analysis(self):
        """This method is invoked when the analysis is started"""
        self._ref = 1

    def process_proxy_history_entry(self, message_info, is_request=False, tool_flag=None, send_date=None, received_date=None,
                                    listener_interface=None, client_ip_address=None, timedout=None,
                                    message_reference=None, proxy_message_info=None, time_delta=None, in_scope=None,
                                    communication_manager=None, invocation=None):
        """
        This method executes the Python script for each HTTP request response item in the HTTP proxy history.
        :return: Returns True if execution was successful else False
        """
        if not message_info:
            return
        header = []
        rows = []
        # Setup API
        request_info = self._helpers.analyzeRequest(message_info)
        url = request_info.getUrl()
        in_scope = self._callbacks.isInScope(url) if in_scope is None else in_scope

        globals = {
            'callbacks': self._callbacks,
            'xerceslib': self._extender.xerces_classloader,
            'plugin_id': self._plugin_id,
            'is_request': is_request,
            'get_json_attributes': self._exported_methods.get_json_attributes,
            'get_json_attribute_by_path': self._exported_methods.get_json_attribute_by_path,
            'get_headers': self._exported_methods.get_headers,
            'get_header': self._exported_methods.get_header,
            'get_cookies': self._exported_methods.get_cookies,
            'get_cookie_attributes': self._exported_methods.get_cookie_attributes,
            'get_parameters': self._exported_methods.get_parameters,
            'get_parameter_name': self._exported_methods.get_parameter_name,
            'compress_gzip': self._exported_methods.compress_gzip,
            'decompress_gzip': self._exported_methods.decompress_gzip,
            'get_content_length': self._exported_methods.get_content_length,
            'get_content_type': self._exported_methods.get_content_type,
            'get_hostname': self._exported_methods.get_hostname,
            'analyze_signatures': self._exported_methods.analyze_signatures,
            'find_error_messages': self._exported_methods.find_error_messages,
            'get_extension_info': self._exported_methods.get_extension_info,
            'find_versions': self._exported_methods.find_versions,
            'find_domains': self._exported_methods.find_domains,
            'decode_html': self._exported_methods.decode_html,
            'url_decode': self._exported_methods.url_decode,
            'analyze_request': self._exported_methods.analyze_request,
            'analyze_response': self._exported_methods.analyze_response,
            'get_jwt': self._exported_methods.get_jwt,
            'decode_jwt': self._exported_methods.decode_jwt,
            'encode_jwt': self._exported_methods.encode_jwt,
            'send_http_message': self._exported_methods.send_http_message,
            'split_http_header': self._exported_methods.split_http_header,
            'has_header': self._exported_methods.has_header,
            'helpers': self._helpers,
            'header': header,
            'rows': rows,
            'url': url,
            'message_info': message_info,
            'request_info': request_info,
            'session': self._session,
            'in_scope': in_scope,
            'ref': self._ref
        }
        if tool_flag:
            globals["tool_flag"] = tool_flag
        if listener_interface:
            globals["listener_interface"] = listener_interface
        if client_ip_address:
            globals["client_ip_address"] = client_ip_address
        if message_reference:
            globals["message_reference"] = message_reference
        if proxy_message_info:
            globals["proxy_message_info"] = proxy_message_info
        # Execute script
        exec(self.ide_pane.compiled_code, globals)
        # Reimport API variables
        self._session = globals['session']
        self._ref = self._ref + 1


class HttpListenerModifier(ModifierTab, IHttpListener):
    """
    Modifies requests and responses on the fly through the IHttpListener interface
    """

    def __init__(self, **kwargs):
        ModifierTab.__init__(self, plugin_id=PluginType.http_listener_modifier, **kwargs)
        self.add(self._ide_pane)

    def processHttpMessage(self, tool_flag, is_request, message_info):
        """
        This method is invoked when an HTTP request is about to be issued, and when an HTTP response has been received.
        :param tool_flag: Burp Suite tool that issued the request
        :param is_request: True or false depending on whether the provided message is a request or response.
        :param message_info: Contains the actual information in form of an IHttpRequestResponse instance.
        :return:
        """
        try:
            if self._ide_pane.activated:
                self.process_proxy_history_entry(message_info, is_request, tool_flag)
        except:
            self._ide_pane.activated = False
            traceback.print_exc(file=self._callbacks.getStderr())
            ErrorDialog.Show(self._extender.parent, traceback.format_exc())


class ProxyListenerModifier(ModifierTab, IProxyListener):
    """
    Modifies requests and responses on the fly through the IProxyListener interface
    """

    def __init__(self, **kwargs):
        ModifierTab.__init__(self, plugin_id=PluginType.proxy_listener_modifier, **kwargs)
        self.add(self._ide_pane)

    def processProxyMessage(self, is_request, message):
        """
        This method is invoked when an HTTP request is about to be issued, and when an HTTP response has been received.
        :param is_request: True or false depending on whether the provided message is a request or response.
        :param message: Contains the actual information in form of an IHttpRequestResponse instance.
        :return:
        """
        try:
            if self._ide_pane.activated:
                self.process_proxy_history_entry(message.getMessageInfo(),
                                                 is_request,
                                                 proxy_message_info=message)
        except:
            self._ide_pane.activated = False
            traceback.print_exc(file=self._callbacks.getStderr())
            ErrorDialog.Show(self._extender.parent, traceback.format_exc())
