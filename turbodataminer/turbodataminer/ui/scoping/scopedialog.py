# -*- coding: utf-8 -*-
"""
This module implements the UI component to display scope dialogs.
"""

__author__ = "Lukas Reiter"
__license__ = "GPL v3.0"
__copyright__ = """Copyright 2022 Lukas Reiter

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

from burp import IParameter
from javax.swing import JPanel
from javax.swing import JButton
from javax.swing import JDialog
from javax.swing import JComboBox
from javax.swing import JOptionPane
from javax.swing import JScrollPane
from java.awt import GridLayout
from java.awt import BorderLayout
from java.awt import Dimension
from turbodataminer.ui.scoping.scopetable import ScopeTable


class BaseScopeDialog(JDialog):
    """
    This dialog implements all functionality to display a scope dialog.
    """

    def __init__(self, owner, title="Check items to be processed"):
        JDialog.__init__(self, owner, title)
        # Set the dialogs layout
        self._owner = owner
        self.setModal(True)
        self.setSize(800, 500)
        self.setMaximumSize(Dimension(800, 500))
        self.setMinimumSize(Dimension(800, 500))
        self.setLayout(BorderLayout())
        self.windowClosing = self._cancel_action
        # Initializing the UI table
        self._scope_table = ScopeTable()
        self._scope_table.setPreferredSize(Dimension(600, 300))
        # table of extracted entries
        scroll_pane = JScrollPane()
        scroll_pane.setViewportView(self._scope_table)
        self.add(scroll_pane, BorderLayout.PAGE_START)
        # add selection
        self._filter_option = JComboBox(["Test only selected items (whitelisting)",
                                        "Exclude all selected items from testing/processing (blacklisting)"])
        self._filter_option.setEditable(False)
        self._filter_option.setSelectedIndex(0)
        self._filter_option.setToolTipText("Specifies whether a whitelisting or blacklisting approach is "
                                           "be applied on the checked items in the table above.")
        self.add(self._filter_option, BorderLayout.CENTER)
        # Add Buttons
        button_panel = JPanel()
        button_panel.setLayout(GridLayout(1, 2))
        b_save = JButton("Ok", actionPerformed=self._save_action)
        button_panel.add(b_save)
        b_cancel = JButton("Cancel", actionPerformed=self._cancel_action)
        button_panel.add(b_cancel)
        self.add(button_panel, BorderLayout.PAGE_END)
        # Initialize variables
        self.canceled = None
        self.filter_results = []
        self.setLocationRelativeTo(owner)

    @property
    def data_model(self):
        return self._scope_table.data_model

    def display(self, header, content):
        """This method displays the scoping dialog."""
        self._scope_table.set_model(header=header, rows=content)
        self.setVisible(True)
        self.pack()

    def _save_action(self, event):
        """
        This method is invoked when the save button is clicked.
        """
        if self._set_filters():
            self.canceled = False
            self.setVisible(False)

    def _cancel_action(self, event):
        """
        This method is invoked when the cancel button is clicked.
        """
        self.canceled = True
        self.setVisible(False)

    @property
    def whitelisting(self):
        return self._filter_option.getSelectedIndex() == 0

    def _set_filters(self):
        """
        This method is called by save_action to set the filter arrays.
        :return:
        """
        self.filter_results = []
        row_count = self.data_model.getRowCount()
        column_count = self.data_model.getColumnCount()
        for row_index in range(0, row_count):
            selected = self.data_model.getValueAt(row_index, 0)
            # Obtain current row values
            row = []
            for column_index in range(1, column_count):
                value = self.data_model.getValueAt(row_index, column_index)
                row.append(value)
            # Add to corresponding filter
            if selected:
                self.filter_results.append(row)
        # Perform checks
        result = len(self.filter_results) != 0
        if not result:
            JOptionPane.showConfirmDialog(self._owner,
                                          "At least one item must be selected.",
                                          "Invalid input ...",
                                          JOptionPane.DEFAULT_OPTION)
        return result


class ParameterScopeDialog(BaseScopeDialog):
    """
    This dialog implements all functionality to display a scope dialog for the given IRequestInfo.
    """

    def __init__(self, owner):
        BaseScopeDialog.__init__(self, owner, title="Check parameters to be processed...")

    @staticmethod
    def get_parameter_name(type):
        rvalue = None
        if type == IParameter.PARAM_URL:
            rvalue = "GET"
        elif type == IParameter.PARAM_BODY:
            rvalue = "POST"
        elif type == IParameter.PARAM_COOKIE:
            rvalue = "Cookie"
        elif type == IParameter.PARAM_XML:
            rvalue = "XML"
        elif type == IParameter.PARAM_XML_ATTR:
            rvalue = "XML Attr"
        elif type == IParameter.PARAM_MULTIPART_ATTR:
            rvalue = "Multipart Attr"
        elif type == IParameter.PARAM_JSON:
            rvalue = "JSON"
        return rvalue

    @staticmethod
    def get_parameter_type(type_name):
        """
        This method returns the parameter type value based on the given descriptive parameter name of the given.
        This method is usually used to convert the value returned by get_parameter_name back to the IParameter type
        value (e.g., "GET" is IParameter.PARAM_URL, "POST" is IParameter.PARAM_BODY, etc.).

        :param type_name (str): The descriptive parameter name that shall be returned as integer.
        :return (str): The integer value that matches the given descriptive parameter name or None.
        """
        if type_name == "GET":
            result = IParameter.PARAM_URL
        elif type_name == "POST":
            result = IParameter.PARAM_BODY
        elif type_name == "Cookie":
            result = IParameter.PARAM_COOKIE
        elif type_name == "XML":
            result = IParameter.PARAM_XML
        elif type_name == "XML Attr":
            result = IParameter.PARAM_XML_ATTR
        elif type_name == "Multipart Attr":
            result = IParameter.PARAM_MULTIPART_ATTR
        elif type_name == "JSON":
            result = IParameter.PARAM_JSON
        else:
            result = None
        return result

    def display(self, request_info):
        """This method displays the scoping dialog."""
        parameters = []
        for parameter in request_info.getParameters():
            type_name = self.get_parameter_name(parameter.getType())
            parameters.append([type_name, parameter.getName(), parameter.getValue()])
        self._scope_table.set_model(header=["Type", "Name", "Example Value"], rows=parameters)
        self.setVisible(True)
        self.pack()

    def match(self, parameter):
        """
        Returns True if the given IParameter is
        :param parameter:
        :return:
        """
        result = False
        for include in self.filter_results:
            result = self.get_parameter_type(include[0]) == parameter.getType() and include[1] == parameter.getName()
            if result:
                break
        return result
