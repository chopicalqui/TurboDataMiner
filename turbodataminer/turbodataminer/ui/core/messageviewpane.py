# -*- coding: utf-8 -*-
"""
This module implements the UI element that displays a single IHttpRequestResponse item.
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


from javax.swing import JPanel
from javax.swing import JSplitPane
from javax.swing import JTabbedPane
from java.awt import BorderLayout
from burp import IHttpRequestResponse


class MessageViewPane(JPanel):
    """
    This class implements a single message information tab
    """

    def __init__(self, extender, message_editor_controller):
        JPanel.__init__(self)
        self.setLayout(BorderLayout())
        self._split_pane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        self._request_details = extender.callbacks.createMessageEditor(message_editor_controller, False)
        self._response_details = extender.callbacks.createMessageEditor(message_editor_controller, False)
        self._split_pane.setTopComponent(self._request_details.getComponent())
        self._split_pane.setBottomComponent(self._response_details.getComponent())
        self.add(self._split_pane)
        self._split_pane.setResizeWeight(0.5)
        self._visible = True

    def set_message_info(self, value):
        if value:
            self.set_visible(True)
            self.set_request(value.getRequest())
            self.set_response(value.getResponse())
        else:
            self.set_visible(True)

    def set_request(self, request):
        if request:
            self._request_details.getComponent().setVisible(True)
            self._request_details.setMessage(request, True)
        else:
            self._request_details.getComponent().setVisible(False)

    def set_response(self, response):
        if response:
            self._response_details.setMessage(response, False)
            self._split_pane.setDividerLocation(0.5)
            self._response_details.getComponent().setVisible(True)
        else:
            self._response_details.getComponent().setVisible(False)

    def set_visible(self, visible):
        if self._visible != visible:
            self._visible = visible
            self.setVisible(visible)


class DynamicMessageViewer(JTabbedPane):
    """
    This class dynamically adds and removes message information in the IdePane
    """

    def __init__(self, extender, message_editor_controller):
        self._message_infos = {}
        self._extender = extender
        self._message_editor_controller = message_editor_controller

    @property
    def message_infos(self):
        return self._message_infos

    @message_infos.setter
    def message_infos(self, value):
        if isinstance(value, dict):
            # Remove invalid elements
            value = {key: message_info for key, message_info in value.items()
                     if isinstance(message_info, IHttpRequestResponse) and isinstance(key, str)}
            # Remove unneeded tabs from UI
            original_titles = set([item for item in self._message_infos.keys()])
            new_titles = set([item for item in value.keys()])
            for tab_title in original_titles - new_titles:
                tab_index = self.indexOfTab(tab_title)
                if 0 <= tab_index:
                    pane = self.getComponentAt(tab_index)
                    self.remove(pane)
            # Update existing tabs
            self._message_infos = value
            for key, message_info in self._message_infos.items():
                tab_index = self.indexOfTab(key)
                if 0 <= tab_index:
                    pane = self.getComponentAt(tab_index)
                    pane.set_message_info(message_info)
                else:
                    pane = MessageViewPane(self._extender, self._message_editor_controller)
                    pane.set_message_info(message_info)
                    self.addTab(key, pane)
