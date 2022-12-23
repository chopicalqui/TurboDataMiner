# -*- coding: utf-8 -*-
"""
The objective of this Burp Suite extension is the flexible and dynamic extraction, correlation, and structured
presentation of information from the Burp Suite project as well as the flexible and dynamic on-the-fly modification
of outgoing or incoming HTTP requests using Python scripts. Thus, Turbo Data Miner shall aid in gaining a better and
faster understanding of the data collected by Burp Suite.
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
import sys
import json
import base64
import traceback
from burp import ITab
from burp import IBurpExtender
from burp import IMessageEditorTab
from burp import IExtensionStateListener
from javax.swing import JScrollPane
from javax.swing import JTabbedPane
from javax.swing import JTextPane
from javax.swing import SwingUtilities
from javax.swing.event import HyperlinkEvent
from java.awt import Frame
from java.awt import Desktop
from java.lang import Thread
from java.net import URL
from java.net import URLClassLoader
from turbodataminer import exports
from turbodataminer.model.scripting import PluginType
from turbodataminer.ui.core.scripting import ErrorDialog
from turbodataminer.ui.analyzers import SiteMapAnalyzer
from turbodataminer.ui.analyzers import ContextMenuAnalyzer
from turbodataminer.ui.analyzers import HttpListenerAnalyzer
from turbodataminer.ui.analyzers import ProxyHistoryAnalyzer
from turbodataminer.ui.modifiers import HttpListenerModifier
from turbodataminer.ui.modifiers import ProxyListenerModifier
from turbodataminer.ui.custommessage import CustomMessageEditorTab
from turbodataminer.ui.core.jtabbedpaneclosable import JTabbedPaneClosable
from turbodataminer.ui.core.analyzers import JTabbedPaneClosableContextMenuAnalyzer


class BurpExtender(IBurpExtender, ITab, IExtensionStateListener):
    """
    This class puts it all together by implementing the burp.IBurpExtender interface
    """

    def __init__(self):
        self.callbacks = None
        self.helpers = None
        self.xerces_classloader = None
        self._main_tabs = None
        # TODO: Update in case of new intel component
        self._pha = None
        self._sma = None
        self._cma = None
        self._hla = None
        self._pla = None
        self._hlm = None
        self._plm = None
        self._mef = None
        self._sct = None
        self._met = None
        self.home_dir = None
        self._about = None
        self.database_files = None

    def registerExtenderCallbacks(self, callbacks):
        """
        :param callbacks:
        :return:
        """
        # keep a reference to our callbacks object
        self.callbacks = callbacks
        # obtain an extension helpers object
        self.helpers = callbacks.getHelpers()
        self.home_dir = os.path.dirname(callbacks.getExtensionFilename())
        # Load data from files
        self.intel_files = exports.IntelFiles(self.home_dir)
        # Set up About tab
        about_file = os.path.join(self.home_dir, "about.html")
        about_file_content = ""
        if os.path.isfile(about_file):
            with open(about_file, "r") as f:
                about_file_content = f.read()
        self._about = JTextPane()
        self._about.setContentType("text/html")
        self._about.putClientProperty("html.disable", None)
        self._about.setEditable(False)
        self._about.setText(about_file_content)
        self._about.addHyperlinkListener(self.hyperlink_listener)
        # load saved configuration
        json_object = {}
        try:
            json_object = self.callbacks.loadExtensionSetting("config")
            if json_object:
                json_object = base64.b64decode(json_object)
                json_object = json.JSONDecoder().decode(json_object)
            else:
                json_object = {}
            # At first load the dictionary does not contain any values.
        except:
            traceback.print_exc(file=self.callbacks.getStderr())
            ErrorDialog.Show(self.parent, traceback.format_exc())
        # Initialize configuration if it is empty or incomplete
        for item in dir(PluginType):
            if not item.startswith("_"):
                key_value = unicode(getattr(PluginType, item))
                if key_value not in json_object:
                    json_object[key_value] = {}
        # set our extension name
        callbacks.setExtensionName("Turbo Data Miner")
        # TODO: Update in case of new intel component
        self._pha = JTabbedPaneClosable(extender=self,
                                        component_class=ProxyHistoryAnalyzer,
                                        configuration=json_object[unicode(PluginType.proxy_history_analyzer)])
        self._sma = JTabbedPaneClosable(extender=self,
                                        component_class=SiteMapAnalyzer,
                                        configuration=json_object[unicode(PluginType.site_map_analyzer)])
        self._cma = JTabbedPaneClosableContextMenuAnalyzer(extender=self,
                                                           component_class=ContextMenuAnalyzer,
                                                           configuration=json_object[
                                                               unicode(PluginType.context_menu_analyzer)])
        self._hla = JTabbedPaneClosable(extender=self,
                                        component_class=HttpListenerAnalyzer,
                                        configuration=json_object[unicode(PluginType.http_listener_analyzer)])
        self._hlm = JTabbedPaneClosable(extender=self,
                                        component_class=HttpListenerModifier,
                                        configuration=json_object[unicode(PluginType.http_listener_modifier)])
        self._plm = JTabbedPaneClosable(extender=self,
                                        component_class=ProxyListenerModifier,
                                        configuration=json_object[unicode(PluginType.proxy_listener_modifier)])
        if self.is_burp_professional:
            from turbodataminer.ui.scannercheck import CustomScannerCheckTab
            self._sct = JTabbedPaneClosable(extender=self,
                                            component_class=CustomScannerCheckTab,
                                            configuration=json_object[unicode(PluginType.scanner_check)])
        self._met = JTabbedPaneClosable(extender=self,
                                        component_class=CustomMessageEditorTab,
                                        configuration=json_object[unicode(PluginType.custom_message_editor)])
        self._main_tabs = JTabbedPane()
        analyzer_tabs = JTabbedPane()
        modifier_tabs = JTabbedPane()
        others_tabs = JTabbedPane()
        analyzer_tabs.addTab("Proxy History Analyzers", self._pha)
        analyzer_tabs.setToolTipTextAt(analyzer_tabs.getTabCount() - 1,
                                       """This analyzer executes the given Python script on each request/response item that is stored in Burp Suite's Proxy
History. Use this analyzer to gather intelligence based on the data already stored in your Burp Suite project.""")
        analyzer_tabs.addTab("Site Map Analyzers", self._sma)
        analyzer_tabs.setToolTipTextAt(analyzer_tabs.getTabCount() - 1,
                                       """This analyzer executes the given Python script on each request/response item that is stored in Burp Suite's Site
Map. Use this analyzer to gather intelligence based on the data already stored in your Burp Suite project.""")
        analyzer_tabs.addTab("Context Menu Analyzers", self._cma)
        analyzer_tabs.setToolTipTextAt(analyzer_tabs.getTabCount() - 1,
                             """In contrast to the Proxy History or Site Map Analyzers, this analyzer only processes request/response items that were
sent via Burp Suite's context menu item Extensions.""")
        analyzer_tabs.addTab("HTTP Listener Analyzers", self._hla)
        analyzer_tabs.setToolTipTextAt(analyzer_tabs.getTabCount() - 1,
                                       """This analyzer implements the interface IHttpListener of the Burp Suite Extender API. Thereby, it executes the current
Python script after each response was received by Burp. Thus, if a request times out, then the Python script is not
called for this request/response pair, and, as a result, this analyzer might not deliver complete results. Use this
analyzer to gather intelligence from requests or responses that are currently sent or received (e.g., sent or
received by Burp's Intruder for example).""")
        modifier_tabs.addTab("HTTP Listener Modifiers", self._hlm)
        analyzer_tabs.setToolTipTextAt(analyzer_tabs.getTabCount() - 1,
                                       """This modifier implements the interface IHttpListener of the Burp Suite Extender API. Thereby, it executes the current
Python script after each response was received by Burp. Thus, if a request times out, then the Python script is not
called for this request/response pair, and, as a result, this analyzer might not deliver complete results. Use this
analyzer to gather intelligence from requests or responses that are currently sent or received (e.g., sent or
received by Burp's Intruder for example).""")
        modifier_tabs.addTab("Proxy Listener Modifiers", self._plm)
        analyzer_tabs.setToolTipTextAt(analyzer_tabs.getTabCount() - 1,
                                       """This analyzer implements the interface IProxyListener of the Burp Suite Extender API. Thereby, it executes the Python
script after each request sent and response received.""")
        if self.is_burp_professional:
            others_tabs.addTab("Custom Scanner Checks", self._sct)
            analyzer_tabs.setToolTipTextAt(analyzer_tabs.getTabCount() - 1,
                                           """This tab implements the interface IScannerCheck of the Burp Suite Extender API. Use it to efficiently implement a custom
    scanner check. Your Python script must implement the following three methods: do_passive_scan, do_active_scan and
    consolidate_duplicate_issues. For more information refer to the IScannerCheck specification.""")
        others_tabs.addTab("Custom Message Editors", self._met)
        analyzer_tabs.setToolTipTextAt(analyzer_tabs.getTabCount() - 1,
                                       """This tab implements the interface IMessageEditorTab of the Burp Suite Extender API. Use it to implement an encoder
and decoder tab, which is automatically added to each message editor. Your Python script must implement the following
three methods: is_enabled, set_message and get_message. For more information refer to the IMessageEditorTab specification.""")
        self._main_tabs.addTab("Analyzers", analyzer_tabs)
        self._main_tabs.setToolTipTextAt(self._main_tabs.getTabCount() - 1,
                                         """The Python scripts in this tab usually structure the extracted information in a GUI table. From there, the results can
be copied (as is or deduplicated) into the clipboard (e.g., to use them as payloads in the Intruder) or exported into
a spreadsheet application for further (statistical) analyses.

In this tab, you will find the following three analyzer plugins to extract and to display information in a
structured way.""")
        self._main_tabs.addTab("Modifiers", modifier_tabs)
        self._main_tabs.setToolTipTextAt(self._main_tabs.getTabCount() - 1,
                                         """Python scripts in this tab allow on the fly modifications on requests sent or responses received by Burp Suite. The
following two modifiers are available.""")
        self._main_tabs.addTab("Others", others_tabs)
        self._main_tabs.setToolTipTextAt(self._main_tabs.getTabCount() - 1,
                                         """This tab contains plugins that do not belong to plugin types Analyzers and Modifiers.""")
        self._main_tabs.addTab("About", JScrollPane(self._about))
        self._main_tabs.setToolTipTextAt(self._main_tabs.getTabCount() - 1,
                                         """This tab contains the documentation about Turbo Intruder's Application Programming Interface (API).""")
        # add the custom tab to Burp Suite's UI
        self.callbacks.addSuiteTab(self)
        self.callbacks.registerExtensionStateListener(self)
        # Manually load Turbo Data Miner's own Apache Xerces library, which was obtained from:
        # http://xerces.apache.org/mirrors.cgi
        # Note that the files integrity was verified prior its incorporation into Turbo Data Miner.
        # For more information about the issue refer to:
        # https://forum.portswigger.net/thread/saxparser-dependency-delimma-499c057a
        xerces_path = os.path.join(self.home_dir, "data", "xercesImpl.jar")
        self.xerces_classloader = URLClassLoader([URL("file://{}".format(xerces_path))],
                                                 Thread.currentThread().getContextClassLoader())
        sys.path.append(os.path.join(self.home_dir, "libs"))
        # Finally, we make the following objects accessible to the TurboMiner package
        import turbominer
        turbominer.helpers = self.helpers
        turbominer.callbacks = self.callbacks

    @property
    def parent(self):
        return SwingUtilities.getRoot(self._main_tabs)

    @property
    def is_burp_professional(self):
        result = False
        for line in self.callbacks.getBurpVersion():
            if line == "Burp Suite Professional":
                result = True
                break
        return result

    @property
    def context_menu_analyzer_tab(self):
        return self._cma

    def getTabCaption(self):
        return "Turbo Miner"

    def getUiComponent(self):
        return self._main_tabs

    def hyperlink_listener(self, event):
        """This event handler processes hyperlink click events"""
        if event.getEventType() == HyperlinkEvent.EventType.ACTIVATED:
            description = event.getDescription()
            try:
                # Follow an internal link
                if description and description[0] == "#":
                    self._about.scrollToReference(description[1:])
                # Follow an external link
                elif Desktop.isDesktopSupported():
                    Desktop.getDesktop().browse(event.getURL().toURI())
            except:
                self.callbacks.printError(traceback.format_exc())

    def extensionUnloaded(self):
        """
        This method is called when the extension is unloaded.
        """
        result = {}
        try:
            # TODO: Update in case of new intel component
            # Store configuration
            result[unicode(PluginType.proxy_history_analyzer)] = self._pha.get_json()
            result[unicode(PluginType.site_map_analyzer)] = self._sma.get_json()
            result[unicode(PluginType.context_menu_analyzer)] = self._cma.get_json()
            result[unicode(PluginType.http_listener_analyzer)] = self._hla.get_json()
            result[unicode(PluginType.http_listener_modifier)] = self._hlm.get_json()
            result[unicode(PluginType.proxy_listener_modifier)] = self._plm.get_json()
            if self.is_burp_professional:
                result[unicode(PluginType.scanner_check)] = self._sct.get_json()
            result[unicode(PluginType.custom_message_editor)] = self._met.get_json()
            result = json.JSONEncoder().encode(result)
            result = base64.b64encode(result)
            self.callbacks.saveExtensionSetting("config", result)
            # Stop all running scripts
            self._pha.stop_scripts()
            self._sma.stop_scripts()
            self._cma.stop_scripts()
            self._hla.stop_scripts()
            self._hlm.stop_scripts()
            self._plm.stop_scripts()
            if self.is_burp_professional:
                self._sct.stop_scripts()
            self._met.stop_scripts()
        except:
            traceback.print_exc(file=self.callbacks.getStderr())
            ErrorDialog.Show(self.parent, traceback.format_exc())
