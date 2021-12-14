# -*- coding: utf-8 -*-
"""
This module implements all functionality to implement a JTabbedPane that allows users to add and remove
tabs in a tab pane.

The code was ported from: https://github.com/PortSwigger/hackvertor/blob/master/src/main/java/burp/JTabbedPaneClosable.java
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
from javax.swing import JLabel
from javax.swing import JTabbedPane
from javax.swing import JTextField
from javax.swing.event import ChangeListener
from java.awt import Font
from java.awt import Color
from java.awt import Dimension
from java.awt import GridBagLayout
from java.awt import GridBagConstraints
from java.awt.event import MouseAdapter
from java.awt.event import FocusAdapter
from java.awt.event import MouseListener
from java.awt.event import ComponentAdapter


class CloseListenerMouseAdapter(MouseAdapter):

    def __init__(self, tab, text_field):
        MouseAdapter.__init__(self)
        self._tab = tab
        self._text_field = text_field

    def mouseClicked(self, event):
        """
        This method is an event for the textField component.
        :param event:
        :return:
        """
        if event.getClickCount() == 1:
            tabbed_pane = self._text_field.getParent().getParent().getParent()
            tabbed_pane.setSelectedIndex(tabbed_pane.indexOfComponent(self._tab))
        elif event.getClickCount() == 2:
            self._text_field.setEditable(True)


class CloseListenerFocusAdapter(FocusAdapter):

    def __init__(self, text_field):
        FocusAdapter.__init__(self)
        self._text_field = text_field

    def focusLost(self, event):
        """
        This method is an event for the textField component.
        :param event:
        :return:
        """
        self._text_field.setEditable(False)


class CloseListener(MouseListener):

    def __init__(self, tab):
        MouseListener.__init__(self)
        self.tab = tab

    def mouseClicked(self, event):
        if isinstance(event.getSource(), JLabel):
            clicked_button = event.getSource()
            tabbed_pane = clicked_button.getParent().getParent().getParent()
            tabbed_pane.clicked_delete = True
            tabbed_pane.remove(self.tab)

    def mousePressed(self, event):
        pass

    def mouseReleased(self, event):
        pass

    def mouseEntered(self, event):
        pass

    def mouseExited(self, event):
        pass


class CloseButtonTab(JPanel):

    def __init__(self, tab, title, icon):
        JPanel.__init__(self)
        self.tab = tab
        self._text_field = JTextField(title)
        self.setOpaque(False)
        self.setLayout(GridBagLayout())
        c = GridBagConstraints()
        c.fill = GridBagConstraints.HORIZONTAL
        c.gridx = 0
        c.gridy = 0
        c.weightx = 0.5
        c.gridwidth = 1
        c.ipadx = 8
        self._text_field.setOpaque(False)
        self._text_field.setBackground(Color(0, 0, 0, 0))
        self._text_field.setBorder(None)
        self._text_field.setEditable(False)
        self._text_field.addMouseListener(CloseListenerMouseAdapter(self.tab, self._text_field))
        self._text_field.addFocusListener(CloseListenerFocusAdapter(self._text_field))
        self.add(self._text_field, c)
        close = JLabel("x")
        close.setFont(Font("Courier", Font.PLAIN, 10))
        close.setPreferredSize(Dimension(10, 10))
        close.setBorder(None)
        close.addMouseListener(CloseListener(self.tab))
        c.gridx = 1
        self.add(close, c)

    def focusLost(self, event):
        """
        This method is an event for the textField component.
        :param event:
        :return:
        """
        self._text_field.setEditable(False)


class JTabbedPaneClosableComponentAdapter(ComponentAdapter):

    def __init__(self, tabbed_pane):
        ComponentAdapter.__init__(self)
        self._tabbed_pane = tabbed_pane

    def componentShown(self, event):
        if self._tabbed_pane.getSelectedIndex() == -1:
            return
        # TODO: Is this for unloading a tab? In this case, we might have to unregister things.


class JTabbedPaneClosableChangeListener(ChangeListener):

    def __init__(self, tabbed_pane):
        ComponentAdapter.__init__(self)
        self._tabbed_pane = tabbed_pane
        self._tab_count = 1

    def stateChanged(self, event):
        if self._tabbed_pane.getSelectedIndex() >= 0:
            if self._tabbed_pane.clicked_delete:
                self._tabbed_pane.clicked_delete = False
                if self._tabbed_pane.getTabCount() > 1:
                    if self._tabbed_pane.getSelectedIndex() == self._tabbed_pane.getTabCount() - 1:
                        self._tabbed_pane.setSelectedIndex(self._tabbed_pane.getTabCount() - 2)
                    return
            if self._tabbed_pane.getTitleAt(self._tabbed_pane.getSelectedIndex()) == "...":
                self._tab_count += 1
                panel = self._tabbed_pane.create_component()
                self._tabbed_pane.remove(self._tabbed_pane.getSelectedIndex())
                self._tabbed_pane.addTab(str(self._tab_count), None, panel)
                self._tabbed_pane.addTab("...", None, JPanel())
                self._tabbed_pane.setSelectedIndex(self._tabbed_pane.getTabCount() - 2)


class JTabbedPaneClosable(JTabbedPane):
    """
    Implements a JTabbedPane which allows users to add and close tabs.
    """
    TAB_COUNT = 1

    def __init__(self, extender, component_class):
        JTabbedPane.__init__(self)
        self.clicked_delete = False
        self._extender = extender
        self.component_class = component_class
        self.addComponentListener(JTabbedPaneClosableComponentAdapter(self))
        self.addTab("1", None, self.create_component())
        self.addTab("...", None, JPanel())
        self.addChangeListener(JTabbedPaneClosableChangeListener(self))

    def create_component(self):
        return self.component_class(self._extender)

    def addTab(self, title, icon, component, tip=None):
        JTabbedPane.addTab(self, title, icon, component, tip)

    def insertTab(self, title, icon, component, tip, index):
        JTabbedPane.insertTab(self, title, icon, component, tip, index)
        if title != "...":
            self.setTabComponentAt(index, CloseButtonTab(component, title, icon))

    def addTabNoExit(self, title, icon, component, tip):
        JTabbedPane.addTab(title, icon, component, tip)