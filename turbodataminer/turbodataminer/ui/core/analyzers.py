# -*- coding: utf-8 -*-
"""
This module implements core functionality for all analyzers.
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

from threading import Lock
from javax.swing import JMenu
from javax.swing import JMenuItem
from burp import IContextMenuFactory
from burp import IContextMenuInvocation
from turbodataminer.ui.core.jtabbedpaneclosable import JTabbedPaneClosable


class ContextMenuAnalyzerMenuItem(JMenuItem):
    def __init__(self, analyzer, title, actionPerformed):
        JMenuItem.__init__(self, title, actionPerformed=actionPerformed)
        self.analyzer = analyzer


class JTabbedPaneClosableContextMenuAnalyzer(JTabbedPaneClosable, IContextMenuFactory):
    """
    Implements a JTabbedPane which allows users to add and close tabs.
    """

    def __init__(self, **kwargs):
        JTabbedPaneClosable.__init__(self, **kwargs)
        self._context_menu_invocation_lock = Lock()
        self.__context_menu_invocation = None
        self.extender.callbacks.registerContextMenuFactory(self)

    @property
    def _context_menu_invocation(self):
        with self._context_menu_invocation_lock:
            result = self.__context_menu_invocation
        return result

    @_context_menu_invocation.setter
    def _context_menu_invocation(self, value):
        with self._context_menu_invocation_lock:
            self.__context_menu_invocation = value

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
            IContextMenuInvocation.CONTEXT_SCANNER_RESULTS,
            IContextMenuInvocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS,
            IContextMenuInvocation.CONTEXT_INTRUDER_ATTACK_RESULTS,
            IContextMenuInvocation.CONTEXT_SEARCH_RESULTS]:
            pha_menu = JMenu("Send to Context Menu Analyzer")
            # Obtain all tab names
            for index in range(0, self.getTabCount() - 1):
                tab_component = self.getTabComponentAt(index)
                component = self.getComponentAt(index)
                title = tab_component.get_title()
                pha_menu.add(ContextMenuAnalyzerMenuItem(component,
                                                         "Tab: {}".format(title),
                                                         actionPerformed=self.menu_invocation_pressed))
            menu_items.append(pha_menu)
        return menu_items

    def menu_invocation_pressed(self, event):
        """This method will be called when one of the menu items are pressed."""
        event.getSource().analyzer.menu_invocation_pressed(self._context_menu_invocation)
