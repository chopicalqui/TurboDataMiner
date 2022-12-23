# -*- coding: utf-8 -*-
"""
This module implements all functionalities for all custom scanner checks.
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
from burp import IScanIssue
from burp import IScannerCheck
from turbodataminer.model.scripting import PluginType
from turbodataminer.model.scripting import PluginCategory
from turbodataminer.ui.core.intelbase import IntelBase
from turbodataminer.ui.core.scripting import ErrorDialog


class ScanIssue(IScanIssue):
    """
    This class is derived from IScanIssue and can be used by Custom Scanner Check plugins to store and register IScanIssues.
    """
    def __init__(self,
                 http_service,
                 url,
                 message_infos,
                 name,
                 detail,
                 severity,
                 type=0,
                 confidence="Certain",
                 background=None,
                 remediation=None):
        self._http_service = http_service
        self._url = url
        self._message_infos = message_infos
        self._name = name
        self._detail = detail
        self._severity = severity
        self._type = type
        self._confidence = confidence
        self._background = background
        self._remediation = remediation

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return self._type

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        return self._background

    def getRemediationBackground(self):
        return self._remediation

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return self._remediation

    def getHttpMessages(self):
        return self._message_infos

    def getHttpService(self):
        return self._http_service


class CustomScannerCheckTab(IntelBase, IScannerCheck):
    """
    This class is used by the CustomTextEditorImplementation class. It implements the logic to write, compile, and
    integrate the code into Burp Suite's message editor tab.
    """

    POST_CODE = """_do_passive_scan = do_passive_scan
_do_active_scan = do_active_scan
_consolidate_duplicate_issues = consolidate_duplicate_issues"""

    def __init__(self, **kwargs):
        IntelBase.__init__(self,
                           plugin_category_id=PluginCategory.scan,
                           executable_on_startup=True,
                           plugin_id=PluginType.scanner_check,
                           post_code=CustomScannerCheckTab.POST_CODE,
                           **kwargs)
        self._do_passive_scan_lock = Lock()
        self._do_passive_scan = None
        self._do_active_scan_lock = Lock()
        self._do_active_scan = None
        self._consolidate_duplicate_issues_lock = Lock()
        self._consolidate_duplicate_issues = None
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
                '_do_passive_scan': self._do_passive_scan,
                '_do_active_scan': self._do_active_scan,
                '_consolidate_duplicate_issues': self._consolidate_duplicate_issues,
                'helpers': self._helpers,
                'core': self._exported_methods,
                'ScanIssue': ScanIssue
            }
            # Execute script
            exec(self.ide_pane.compiled_code, globals)
            # Reimport API method implementations
            self.do_passive_scan = globals['_do_passive_scan']
            self.do_active_scan = globals['_do_active_scan']
            self.consolidate_duplicate_issues = globals['_consolidate_duplicate_issues']
            # Register IScannerCheck
            self._extender.callbacks.registerScannerCheck(self)
        except:
            self._ide_pane.activated = False
            self.stop_analysis()
            traceback.print_exc(file=self._extender.callbacks.getStdout())
            ErrorDialog.Show(self._extender.parent, traceback.format_exc())

    def stop_analysis(self):
        # Unregister IScannerCheck
        self._extender.callbacks.removeScannerCheck(self)
        # Delete current method definition
        self.do_passive_scan = None
        self.do_active_scan = None
        self.consolidate_duplicate_issues = None
        self.session = {}

    @property
    def do_passive_scan(self):
        with self._do_passive_scan_lock:
            result = self._do_passive_scan
        return result

    @do_passive_scan.setter
    def do_passive_scan(self, value):
        with self._do_passive_scan_lock:
            self._do_passive_scan = value

    @property
    def do_active_scan(self):
        with self._do_active_scan_lock:
            result = self._do_active_scan
        return result

    @do_active_scan.setter
    def do_active_scan(self, value):
        with self._do_active_scan_lock:
            self._do_active_scan = value

    @property
    def consolidate_duplicate_issues(self):
        with self._consolidate_duplicate_issues_lock:
            result = self._consolidate_duplicate_issues
        return result

    @consolidate_duplicate_issues.setter
    def consolidate_duplicate_issues(self, value):
        with self._consolidate_duplicate_issues_lock:
            self._consolidate_duplicate_issues = value

    @property
    def session(self):
        with self._session_lock:
            result = self._session
        return result

    @session.setter
    def session(self, value):
        with self._session_lock:
            self._session = value

    def process_proxy_history_entry(self, message_info, is_request=False, tool_flag=None, send_date=None,
                                    received_date=None, listener_interface=None, client_ip_address=None,
                                    timedout=None, message_reference=None, proxy_message_info=None, time_delta=None,
                                    in_scope=None, communication_manager=None, invocation=None):
        pass

    def doPassiveScan(self, message_info):
        result = []
        try:
            if self.do_passive_scan:
                result = self.do_passive_scan(message_info, self.session)
        except:
            self._ide_pane.activated = False
            self.stop_analysis()
            traceback.print_exc(file=self._extender.callbacks.getStderr())
            ErrorDialog.Show(self._extender.parent, traceback.format_exc())
        return result

    def doActiveScan(self, message_info, insertion_point):
        result = []
        try:
            if self.do_active_scan:
                result = self.do_active_scan(message_info, insertion_point, self.session)
        except:
            self._ide_pane.activated = False
            self.stop_analysis()
            traceback.print_exc(file=self._extender.callbacks.getStderr())
            ErrorDialog.Show(self._extender.parent, traceback.format_exc())
        return result

    def consolidateDuplicateIssues(self, existing_issue, new_issue):
        result = -1
        try:
            if self.consolidate_duplicate_issues:
                result = self.consolidate_duplicate_issues(existing_issue, new_issue)
        except:
            self._ide_pane.activated = False
            self.stop_analysis()
            traceback.print_exc(file=self._extender.callbacks.getStderr())
            ErrorDialog.Show(self._extender.parent, traceback.format_exc())
        return result
