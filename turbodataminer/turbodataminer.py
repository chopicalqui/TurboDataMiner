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
import threading
import traceback
from burp import ITab
from burp import IBurpExtender
from burp import IMessageEditorTab
from burp import IContextMenuFactory
from burp import IContextMenuInvocation
from burp import IExtensionStateListener
from burp import IMessageEditorTabFactory
from threading import Lock
from javax.swing import JScrollPane
from javax.swing import JTabbedPane
from javax.swing import JMenuItem
from javax.swing import JTextPane
from javax.swing import SwingUtilities
from javax.swing.event import HyperlinkEvent
from java.awt import Desktop
from java.lang import Thread
from java.net import URL
from java.net import URLClassLoader
from turbodataminer.model.scripting import PluginType
from turbodataminer.model.scripting import PluginCategory
from turbodataminer.model.intelligence import IntelDataModel
from turbodataminer.ui.core.scripting import ErrorDialog
from turbodataminer.ui.analyzers import AnalyzerBase
from turbodataminer.ui.analyzers import SiteMapAnalyzer
from turbodataminer.ui.analyzers import HttpListenerAnalyzer
from turbodataminer.ui.analyzers import ProxyHistoryAnalyzer
from turbodataminer.ui.modifiers import HttpListenerModifier
from turbodataminer.ui.modifiers import ProxyListenerModifier
from turbodataminer.ui.custommessage import CustomMessageEditorTab
from turbodataminer.ui.custommessage import CustomTextEditorImplementation
from turbodataminer.ui.core.jtabbedpaneclosable import JTabbedPaneClosable


class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IMessageEditorTabFactory, IExtensionStateListener):
    """
    This class puts it all together by implementing the burp.IBurpExtender interface
    """

    def __init__(self):
        self.callbacks = None
        self.helpers = None
        self.xerces_classloader = None
        self._main_tabs = None
        self._pha = None
        self._sma = None
        self._hla = None
        self._pla = None
        self._hlm = None
        self._plm = None
        self._mef = None
        self.custom_editor_tab = None
        self.home_dir = None
        self.parent = None
        self._context_menu_invocation = None
        self._about = None

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
        # Set up About tab
        about_file = os.path.join(self.home_dir, "about.html")
        about_file_content = ""
        if os.path.isfile(about_file):
            with open(about_file, "r") as f:
                about_file_content = f.read()
        self._about = JTextPane()
        self._about.setContentType("text/html")
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
        self._pha = JTabbedPaneClosable(self,
                                        ProxyHistoryAnalyzer,
                                        configuration=json_object[unicode(PluginType.proxy_history_analyzer)])
        self._sma = JTabbedPaneClosable(self,
                                        SiteMapAnalyzer,
                                        configuration=json_object[unicode(PluginType.site_map_analyzer)])
        self._hla = JTabbedPaneClosable(self,
                                        HttpListenerAnalyzer,
                                        configuration=json_object[unicode(PluginType.http_listener_analyzer)])
        self._hlm = JTabbedPaneClosable(self,
                                        HttpListenerModifier,
                                        configuration=json_object[unicode(PluginType.http_listener_modifier)])
        self._plm = JTabbedPaneClosable(self,
                                        ProxyListenerModifier,
                                        configuration=json_object[unicode(PluginType.proxy_listener_modifier)])
        self.custom_editor_tab = CustomMessageEditorTab(self)
        self._main_tabs = JTabbedPane()
        analyzer_tabs = JTabbedPane()
        modifier_tabs = JTabbedPane()
        analyzer_tabs.addTab("Proxy History Analyzers", self._pha)
        analyzer_tabs.addTab("Site Map Analyzers", self._sma)
        analyzer_tabs.addTab("HTTP Listener Analyzers", self._hla)
        modifier_tabs.addTab("HTTP Listener Modifiers", self._hlm)
        modifier_tabs.addTab("Proxy Listener Modifiers", self._plm)
        self._main_tabs.addTab("Analyzers", analyzer_tabs)
        self._main_tabs.addTab("Modifiers", modifier_tabs)
        self._main_tabs.addTab("Custom Message Editor", self.custom_editor_tab)
        self._main_tabs.addTab("About", JScrollPane(self._about))
        # add the custom tab to Burp Suite's UI
        self.callbacks.addSuiteTab(self)
        self.callbacks.customizeUiComponent(self._main_tabs)
        self.callbacks.customizeUiComponent(self._pha)
        self.callbacks.customizeUiComponent(self._hla)
        self.callbacks.customizeUiComponent(self._hlm)
        self.callbacks.customizeUiComponent(self._plm)
        self.callbacks.registerContextMenuFactory(self)
        self.callbacks.registerExtensionStateListener(self)
        self.callbacks.registerMessageEditorTabFactory(self)
        self.parent = SwingUtilities.getRoot(self._main_tabs)
        # Manually load Turbo Data Miner's own Apache Xerces library, which was obtained from:
        # http://xerces.apache.org/mirrors.cgi
        # Note that the files integrity was verified prior its incorporation into Turbo Data Miner.
        # For more information about the issue refer to:
        # https://forum.portswigger.net/thread/saxparser-dependency-delimma-499c057a
        xerces_path = os.path.join(self.home_dir, "data", "xercesImpl.jar")
        self.xerces_classloader = URLClassLoader([URL("file://{}".format(xerces_path))],
                                                 Thread.currentThread().getContextClassLoader())
        sys.path.append(os.path.join(self.home_dir, "data", "libs"))

    def getTabCaption(self):
        return "Turbo Miner"

    def getUiComponent(self):
        return self._main_tabs

    def createMenuItems(self, invocation):
        """
        This method will be called by Burp Suite when the user invokes a context menu anywhere within Burp Suite. The
        factory can then provide any custom context menu items that should be displayed in the context menu, based on
        the details of the menu invocation.

        :param invocation An object that implements the IMessageEditorTabFactory interface, which the extension can
        query to obtain details of the context menu invocation.
        :return: A list of custom menu items (which may include sub-menus, checkbox menu items, etc.) that should be
        displayed. Extensions may return null from this method, to indicate that no menu items are required.
        """
        self._context_menu_invocation = invocation
        menu_items = []
        if invocation.getInvocationContext() in [
            IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
            IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE,
            IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST,
            IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE,
            IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE,
            IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE,
            IContextMenuInvocation.CONTEXT_PROXY_HISTORY,
            IContextMenuInvocation.CONTEXT_INTRUDER_ATTACK_RESULTS]:
            menu_items.append(JMenuItem("Process in Turbo Data Miner (Proxy History Analyzer tab)",
                                        actionPerformed=self.menu_invocation_pressed))
        return menu_items

    def createNewInstance(self, controller, editable):
        return CustomTextEditorImplementation(self, controller, editable)

    def menu_invocation_pressed(self, event):
        """This method will be called when one of the menu items are pressed."""
        self._pha.menu_invocation_pressed(self._context_menu_invocation)

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
            result[unicode(PluginType.http_listener_analyzer)] = self._hla.get_json()
            result[unicode(PluginType.http_listener_modifier)] = self._hlm.get_json()
            result[unicode(PluginType.proxy_listener_modifier)] = self._plm.get_json()
            result[unicode(PluginType.custom_message_editor)] = self.custom_editor_tab.get_json()
            result = json.JSONEncoder().encode(result)
            result = base64.b64encode(result)
            self.callbacks.saveExtensionSetting("config", result)
            # Stop all running scripts
            self._pha.stop_scripts()
            self._sma.stop_scripts()
            self._hla.stop_scripts()
            self._hlm.stop_scripts()
            self._plm.stop_scripts()
            # TODO: self.custom_editor_tab.get_json()
        except:
            traceback.print_exc(file=self.callbacks.getStderr())
            ErrorDialog.Show(self.parent, traceback.format_exc())
