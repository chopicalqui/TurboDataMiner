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

import traceback
from javax.swing import JPanel
from javax.swing import JLabel
from javax.swing import JTextField
from javax.swing import JTabbedPane
from javax.swing import JOptionPane
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
from turbodataminer.ui.analyzers import HttpListenerAnalyzer
from turbodataminer.ui.modifiers import HttpListenerModifier
from turbodataminer.ui.modifiers import ProxyListenerModifier
from turbodataminer.ui.custommessage import CustomMessageEditorTab
from turbodataminer.ui.core.intelbase import IntelBaseConfiguration


class CloseListenerMouseAdapter(MouseAdapter):
    """
    Each tab contains a JTextField before the x. This listener class enables editing the JTextField if the user
    double-clicks on it.
    """

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
        tabbed_pane = self._text_field.getParent().getParent().getParent()
        tabbed_pane.setSelectedIndex(tabbed_pane.indexOfComponent(self._tab))
        if event.getClickCount() == 2:
            self._text_field.setEditable(True)


class CloseListenerFocusAdapter(FocusAdapter):
    """
    Each tab contains a JTextField before the x. CloseListenerMouseAdapter enables editing the JTextField if the user
    double-clicks on it. This class is the counterpart that disables editing as soon as the focus is lost.
    """

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

    def __init__(self, extender, tab):
        MouseListener.__init__(self)
        self._extender = extender
        self._tab = tab

    def mouseClicked(self, event):
        """
        This method is called when button x is clicked to close the tab.
        :param event:
        :return:
        """
        if isinstance(event.getSource(), JLabel):
            clicked_button = event.getSource()
            tabbed_pane = clicked_button.getParent().getParent().getParent()
            result = self._pre_closing_activities()
            if result != JOptionPane.CANCEL_OPTION:
                # Remove tab from UI
                tabbed_pane.clicked_delete = True
                tabbed_pane.remove(self._tab)

    def _pre_closing_activities(self):
        """
        This method performs all necessary activities before the tab can be closed.
        :return:
        """
        # Check if the script has to be saved and continue operation based on the user's decision
        result = self._tab.ide_pane.save_current_script()
        if result != JOptionPane.CANCEL_OPTION:
            # Closing the tab is like clicking the Stop button and as a result, we re-enable the IDE pane components
            # as well as call the cleanup function.
            self._tab.ide_pane.activated = False
            self._tab.ide_pane.stop_analysis_function()
            # Remove Burp Suite Listener
            JTabbedPaneClosable.remove_listener(self._extender.callbacks, self._tab)
        return result

    def mousePressed(self, event):
        pass

    def mouseReleased(self, event):
        pass

    def mouseEntered(self, event):
        pass

    def mouseExited(self, event):
        pass


class CloseButtonTab(JPanel):

    def __init__(self, extender, tab, title, icon):
        JPanel.__init__(self)
        self._extender = extender
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
        # The following two listeners enable editing in case the user double clicks on the text field and disables
        # editing as soon as the focus is lost.
        self._text_field.addMouseListener(CloseListenerMouseAdapter(self.tab, self._text_field))
        self._text_field.addFocusListener(CloseListenerFocusAdapter(self._text_field))
        self.add(self._text_field, c)
        close = JLabel("x")
        close.setFont(Font("Courier New", Font.PLAIN, 10))
        close.setPreferredSize(Dimension(10, 10))
        close.setBorder(None)
        close.addMouseListener(CloseListener(self._extender, self.tab))
        c.gridx = 1
        self.add(close, c)

    def focusLost(self, event):
        """
        This method is an event for the textField component.
        :param event:
        :return:
        """
        self._text_field.setEditable(False)

    def get_title(self):
        """
        This method returns the tab's title.
        :return:
        """
        return self._text_field.getText()


class JTabbedPaneClosableComponentAdapter(ComponentAdapter):

    def __init__(self, tabbed_pane):
        ComponentAdapter.__init__(self)
        self._tabbed_pane = tabbed_pane

    def componentShown(self, event):
        if self._tabbed_pane.getSelectedIndex() == -1:
            return


class JTabbedPaneClosableChangeListener(ChangeListener):

    def __init__(self, tabbed_pane, tab_count):
        ComponentAdapter.__init__(self)
        self._tabbed_pane = tabbed_pane
        self._tab_count = tab_count

    def stateChanged(self, event):
        if self._tabbed_pane.getSelectedIndex() >= 0:
            if self._tabbed_pane.clicked_delete:
                self._tabbed_pane.clicked_delete = False
                if self._tabbed_pane.getTabCount() > 1:
                    if self._tabbed_pane.getSelectedIndex() == self._tabbed_pane.getTabCount() - 1:
                        self._tabbed_pane.setSelectedIndex(self._tabbed_pane.getTabCount() - 2)
                    return
            # Do not make an elif here
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

    def __init__(self, extender, component_class, configuration=None):
        JTabbedPane.__init__(self)
        tab_count = 0
        print("Load: {}".format(component_class.__name__))
        self.clicked_delete = False
        self.extender = extender
        self._component_class = component_class
        self.addComponentListener(JTabbedPaneClosableComponentAdapter(self))
        # Read configuration and load plugins
        if configuration and "tabs" in configuration:
            for tab_index in configuration["tabs"]:
                if tab_index in configuration:
                    tab_info = configuration[tab_index]
                    if "title" in tab_info and "script_info" in tab_info:
                        title = tab_info["title"]
                        print("- Load tab: {}".format(title))
                        # Parse the plugin's configuration
                        try:
                            script_info = IntelBaseConfiguration(tab_info["script_info"])
                        except:
                            traceback.print_exc(file=self.extender.callbacks.getStderr())
                            script_info = IntelBaseConfiguration()
                        # Load and add plugin UI with the configuration
                        component = self.create_component(script_info)
                        self.addTab(title, None, component)
                        tab_count += 1
                        # Launch plugin script it has been running at the last unload
                        if script_info.activated:
                            component.ide_pane.activated = True
                            component.ide_pane.start_stop_script()
        if tab_count == 0:
            self.addTab("1", None, self.create_component())
            tab_count += 1
        self.addTab("...", None, JPanel())
        self.addChangeListener(JTabbedPaneClosableChangeListener(self, tab_count))

    def create_component(self, configuration=None):
        return self._component_class(extender=self.extender, configuration=configuration, closable_tabbed_pane=self)

    def addTab(self, title, icon, component, tip=None):
        JTabbedPane.addTab(self, title, icon, component, tip)
        # Register Burp Suite listeners
        self.register_listener(self.extender.callbacks, component)

    def insertTab(self, title, icon, component, tip, index):
        JTabbedPane.insertTab(self, title, icon, component, tip, index)
        if title != "...":
            self.setTabComponentAt(index, CloseButtonTab(self.extender, component, title, icon))

    def get_json(self):
        """
        This method returns the tab's current state. The method is used by Turbo Miner to persist the current
        configuration.
        :return:
        """
        tabs = []
        result = {"tabs": tabs}
        for i in range(0, self.getTabCount() - 1):
            index = str(i)
            tab_component = self.getTabComponentAt(i)
            component = self.getComponentAt(i)
            title = tab_component.get_title()
            tabs.append(index)
            result[index] = {"title": title, "script_info": component.get_json()}
        return result

    def stop_scripts(self):
        """
        This method sends the stop signal to all intel tabs. This method is called by the extender when the app
        is unloaded.
        :return:
        """
        for i in range(0, self.getTabCount() - 1):
            component = self.getComponentAt(i)
            # Unloading the app is like clicking the Stop button and as a result, we re-enable the IDE pane components
            # as well as call the cleanup functions.
            component.ide_pane.activated = False
            component.ide_pane.stop_analysis_function()

    @staticmethod
    def register_listener(callbacks, component):
        """
        This static method performs all Burp Suite listener registrations
        :param callbacks:
        :param component:
        :return:
        """
        # TODO: Update in case of new intel component
        if isinstance(component, HttpListenerAnalyzer):
            callbacks.registerHttpListener(component)
        elif isinstance(component, HttpListenerModifier):
            callbacks.registerHttpListener(component)
        elif isinstance(component, ProxyListenerModifier):
            callbacks.registerProxyListener(component)
        # Note that CustomMessageEditorTab is registered in turbominer.ui.custommessage.CustomMessageEditorTab
        # Note that CustomScannerCheckTab is registered in turbominer.ui.scannercheck.CustomScannerCheckTab

    @staticmethod
    def remove_listener(callbacks, component):
        """
        This static method performs all Burp Suite listener registrations
        :param callbacks:
        :param component:
        :return:
        """
        # TODO: Update in case of new intel component
        if isinstance(component, HttpListenerAnalyzer):
            callbacks.removeHttpListener(component)
        elif isinstance(component, HttpListenerModifier):
            callbacks.removeHttpListener(component)
        elif isinstance(component, ProxyListenerModifier):
            callbacks.removeProxyListener(component)
        # Note that CustomMessageEditorTab is registered in turbominer.ui.custommessage.CustomMessageEditorTab
        # Note that CustomScannerCheckTab is registered in turbominer.ui.scannercheck.CustomScannerCheckTab
