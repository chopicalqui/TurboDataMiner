# -*- coding: utf-8 -*-
"""
This module implements all functionalities for all analyzer GUIs.
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
import threading
from threading import Lock
from threading import RLock
from burp import IHttpListener
from burp import IBurpExtenderCallbacks
from javax.swing import JSplitPane
from javax.swing import JScrollPane
from java.awt import BorderLayout
from turbodataminer.ui.core.intelbase import IntelBase
from turbodataminer.ui.core.scripting import ErrorDialog
from turbodataminer.ui.core.inteltable import IntelTable
from turbodataminer.ui.core.messageviewpane import MessageViewPane
from turbodataminer.ui.core.messageviewpane import DynamicMessageViewer
from turbodataminer.model.scripting import PluginType
from turbodataminer.model.scripting import PluginCategory
from turbodataminer.model.intelligence import IntelDataModel
from turbodataminer.model.intelligence import IntelDataModelEntry


class IntelTab(IntelBase):
    """
    This abstract class holds all GUI elements like JTable or IDEPanel to implement to implement an analyzer GUI
    """

    def __init__(self, extender, id, plugin_id):
        """
        :param extender:
        :param id: Usually the class name. This information is used for storing the current state in Burp Suite in case
        the extension is unloaded.
        :param plugin_id:
        :param script_dir: The files system directory where the scripts are stored
        """
        IntelBase.__init__(self, extender, id, plugin_id, PluginCategory.analyzer)
        self._table_model_lock = RLock()
        self._data_model = IntelDataModel()
        self._table = IntelTable(self, self._data_model, self._table_model_lock)
        self._message_info_pane = MessageViewPane(extender, self._table)

        split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        split_pane.setOneTouchExpandable(True)
        self.add(split_pane, BorderLayout.CENTER)

        # table of extracted entries
        scroll_pane = JScrollPane()
        scroll_pane.setViewportView(self._table)
        split_pane.setLeftComponent(scroll_pane)

        # tabbed pane containing IDE and table details
        self._work_tabbed_pane = DynamicMessageViewer(extender, self._table)
        split_pane.setRightComponent(self._work_tabbed_pane)

        self._work_tabbed_pane.addTab("Python", self._ide_pane)
        self._work_tabbed_pane.addTab("Message Information", self._message_info_pane)

        split_pane.setDividerLocation(0.5)

    @property
    def message_info_pane(self):
        return self._message_info_pane

    @property
    def work_tab_pane(self):
        return self._work_tabbed_pane

    @property
    def data_model(self):
        return self._data_model

    @property
    def request_details(self):
        return self._request_details

    @property
    def response_details (self):
        return self._response_details

    def process_proxy_history_entry(self, message_info, is_request=False, tool_flag=None, send_date=None, received_date=None,
                                    listener_interface=None, client_ip_address=None, timedout=None,
                                    message_reference=None, proxy_message_info=None, time_delta=None, row_count=None,
                                    in_scope=None):
        """
        This method executes the Python script for each HTTP request response item in the HTTP proxy history.
        :return: Returns True if exection was successful else False
        """
        if not message_info:
            return
        header = []
        rows = []
        message_infos = {}
        # Setup API
        request_info = self._helpers.analyzeRequest(message_info)
        url = request_info.getUrl()
        in_scope = self._callbacks.isInScope(url) if in_scope is None else in_scope

        globals = {
            'callbacks': self._callbacks,
            'xerceslib': self._extender.xerces_classloader,
            'plugin_id': self._plugin_id,
            'row_count': row_count,
            'get_json_attributes': self._exported_methods.get_json_attributes,
            'get_json_attribute_by_path': self._exported_methods.get_json_attribute_by_path,
            'get_headers': self._exported_methods.get_headers,
            'get_parameters': self._exported_methods.get_parameters,
            'get_parameter_name': self._exported_methods.get_parameter_name,
            'get_header': self._exported_methods.get_header,
            'get_cookies': self._exported_methods.get_cookies,
            'get_cookie_attributes': self._exported_methods.get_cookie_attributes,
            'compress_gzip': self._exported_methods.compress_gzip,
            'decompress_gzip': self._exported_methods.decompress_gzip,
            'get_hostname': self._exported_methods.get_hostname,
            'get_content_length': self._exported_methods.get_content_length,
            'get_content_type': self._exported_methods.get_content_type,
            'analyze_signatures': self._exported_methods.analyze_signatures,
            'get_extension_info': self._exported_methods.get_extension_info,
            'find_versions': self._exported_methods.find_versions,
            'find_domains': self._exported_methods.find_domains,
            'decode_html': self._exported_methods.decode_html,
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
            'message_infos': message_infos,
            'request_info': request_info,
            'session': self._session,
            'in_scope': in_scope,
            'ref': self._ref
        }
        if tool_flag:
            globals["tool_flag"] = tool_flag
        if send_date:
            globals["sent_date"] = send_date
        if received_date:
            globals["received_date"] = received_date
        if listener_interface:
            globals["listener_interface"] = listener_interface
        if client_ip_address:
            globals["client_ip_address"] = client_ip_address
        if timedout is not None:
            globals["timedout"] = timedout
        if message_reference:
            globals["message_reference"] = message_reference
        if time_delta:
            globals["time_delta"] = time_delta
        # Execute compiled code
        exec(self.ide_pane.compiled_code, globals)
        # Reimport writable API variables
        self._session = globals['session']
        rows = globals['rows']
        header = globals['header']
        message_infos = globals['message_infos']
        # Create new table row
        entries = []
        for row in rows:
            if isinstance(row, list):
                entries.append(IntelDataModelEntry(row, message_info, message_infos))
            else:
                entries.append(IntelDataModelEntry([row], message_info, message_infos))
        # Setup table header
        if self._ref <= 1:
            self._data_model.set_header(header, reset_column_count=True)
        elif row_count and self._ref == (row_count - 1) and not self._data_model.get_header() and header:
            self._data_model.set_header(header, reset_column_count=True)
        # Add new row to table
        with self._table_model_lock:
            self._data_model.add_rows(entries)
        self._ref = self._ref + 1


class AnalyzerBase(IntelTab):
    """
    This class implements the base functionality for the proxy history and site map analyzer
    """

    def __init__(self, extender, name, type):
        IntelTab.__init__(self, extender, name, type)
        self._process_thread = None
        self._lock = Lock()

    def _start_analysis(self, entries):
        """This method is invoked when the analysis is started"""
        self._ref = 1

        try:
            self._process_thread = threading.Thread(target=self.process_proxy_history_entries, args=(entries, ))
            self._process_thread.daemon = True
            self._process_thread.start()
        except:
            traceback.print_exc(file=self._callbacks.getStderr())
            ErrorDialog.Show(self._extender.parent, traceback.format_exc())
            self._ide_pane.activated = False

    def stop_analysis(self):
        """This method is invoked when the analysis is stopped"""
        self._process_thread.join()

    def process_proxy_history_entries(self, entries):
        """Iterates through all entries of the HTTP proxy history and processes them."""
        try:
            self._data_model.clear_data()
            row_count = len(entries)
            for message_info in entries:
                if not self._ide_pane.activated:
                    break
                self.process_proxy_history_entry(message_info, IBurpExtenderCallbacks.TOOL_PROXY, row_count=row_count)
            self._ide_pane.activated = False
        except:
            traceback.print_exc(file=self._callbacks.getStderr())
            ErrorDialog.Show(self._extender.parent, traceback.format_exc())
            self._ide_pane.activated = False

    def _menu_invocation_pressed(self, invocation):
        """
        This method iterates through all selected message info items that were sent to Turbo Data Miner via
        Turbo Data Miner's context menu.
        """
        try:
            self._ref = 1
            self._ide_pane.compile()
            self._ide_pane.activated = True
            messages = invocation.getSelectedMessages()
            row_count = len(messages)
            for message_info in messages:
                self.process_proxy_history_entry(message_info,
                                                 invocation.getToolFlag(),
                                                 in_scope=True,
                                                 row_count=row_count)
            self._ide_pane.activated = False
        except:
            traceback.print_exc(file=self._callbacks.getStderr())
            ErrorDialog.Show(self._extender.parent, traceback.format_exc())
            self._ide_pane.activated = False

    def menu_invocation_pressed(self, invocation):
        """This method is invoked when Turbo Data Miner's context menu is selected"""
        self._ref = 1

        try:
            self._process_thread = threading.Thread(target=self._menu_invocation_pressed, args=(invocation, ))
            self._process_thread.daemon = True
            self._process_thread.start()
        except:
            traceback.print_exc(file=self._callbacks.getStderr())
            ErrorDialog.Show(self._extender.parent, traceback.format_exc())
            self._ide_pane.activated = False


class ProxyHistoryAnalyzerBase(AnalyzerBase):
    """
    This class implements the proxy history analyzer
    """

    def __init__(self, extender):
        AnalyzerBase.__init__(self, extender, ProxyHistoryAnalyzerBase.__name__, PluginType.proxy_history_analyzer)

    def start_analysis(self):
        with self._lock:
            entries = [item for item in self._callbacks.getProxyHistory()]
        self._start_analysis(entries)


class SiteMapAnalyzerBase(AnalyzerBase):
    """
    This class implements the site map analyzer
    """

    def __init__(self, extender):
        AnalyzerBase.__init__(self, extender, SiteMapAnalyzerBase.__name__, PluginType.site_map_analyzer)

    def start_analysis(self):
        with self._lock:
            entries = [item for item in self._callbacks.getSiteMap(None)]
        self._start_analysis(entries)


class HttpListenerAnalyzer(IntelTab, IHttpListener):
    """
    Analyzes information delivered through the IHttpListener interface
    """

    def __init__(self, extender):
        IntelTab.__init__(self, extender, HttpListenerAnalyzer.__name__, PluginType.http_listener_analyzer)

    def start_analysis(self):
        """This method is invoked when the analysis is started"""
        self._ref = 1

    def processHttpMessage(self, tool_flag, is_request, message_info):
        """
        This method is invoked when an HTTP request is about to be issued, and when an HTTP response has been received.
        :param tool_flag: Burp Suite tool that issued the request
        :param is_request: True or false depending on whether the provided message is a request or response.
        :param message_info: Contains the actual information in form of an IHttpRequestResponse instance.
        :return:
        """
        try:
            if self._ide_pane.activated and not is_request:
                self.process_proxy_history_entry(message_info, is_request, tool_flag)
        except:
            traceback.print_exc(file=self._callbacks.getStderr())
            ErrorDialog.Show(self._extender.parent, traceback.format_exc())
            self._ide_pane.activated = False
