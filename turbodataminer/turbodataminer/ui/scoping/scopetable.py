# -*- coding: utf-8 -*-
"""
This module implements the UI component to display scope information.
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

import traceback
from javax.swing import JMenu
from javax.swing import JTable
from javax.swing import JMenuItem
from javax.swing import JPopupMenu
from javax.swing import JOptionPane
from java.lang import Float
from java.lang import Double
from java.lang import String
from java.lang import Integer
from javax.swing.table import DefaultTableCellRenderer
from turbodataminer.model.scope import BaseScopeDataModel


class ScopeDefaultTableCellRenderer(DefaultTableCellRenderer):
    """
    This class implements the default JTable background.
    """

    def __init__(self):
        DefaultTableCellRenderer.__init__(self)

    def getTableCellRendererComponent(self, table, value, is_selected, has_focus, row, column):
        """This method is called by the UI table to calculate a row's background color."""
        result = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, is_selected, has_focus, row, column)
        if not is_selected:
            result.setBackground(None)
        return result


class ScopeTable(JTable):
    """
    The component shows scope information in the graphical user interface in a JTable.
    """
    def __init__(self, data_model=BaseScopeDataModel()):
        JTable.__init__(self, data_model)
        self.setDefaultRenderer(Integer, ScopeDefaultTableCellRenderer())
        self.setDefaultRenderer(String, ScopeDefaultTableCellRenderer())
        self.setDefaultRenderer(Float, ScopeDefaultTableCellRenderer())
        self.setDefaultRenderer(Double, ScopeDefaultTableCellRenderer())
        self.setAutoCreateRowSorter(True)
        self.data_model = data_model
        # table pop menu
        self._popup_menu = JPopupMenu()
        # Clear Table
        self._popup_menu.add(JMenuItem("Check all rows",
                                       actionPerformed=self._select_all_menu_pressed))
        self._popup_menu.add(JMenuItem("Uncheck all rows",
                                       actionPerformed=self._unselect_all_menu_pressed))
        self._popup_menu.addSeparator()
        self._popup_menu.add(JMenuItem("Check all selected rows",
                                       actionPerformed=self._select_all_selected_menu_pressed))
        self._popup_menu.add(JMenuItem("Uncheck all selected rows",
                                       actionPerformed=self._unselect_all_selected_menu_pressed))
        self._popup_menu.addSeparator()
        self._popup_menu.add(JMenuItem("Invert selection",
                                       actionPerformed=self._invert_selection_menu_pressed))
        self.setComponentPopupMenu(self._popup_menu)

    def set_model(self, header, rows):
        self.data_model.set_header(header)
        self.data_model.set_content(rows)

    def _select_all_menu_pressed(self, event):
        self._update_all_rows(True)

    def _unselect_all_menu_pressed(self, event):
        self._update_all_rows(False)

    def _select_all_selected_menu_pressed(self, event):
        self._update_selected_rows(True)

    def _unselect_all_selected_menu_pressed(self, event):
        self._update_selected_rows(False)

    def _invert_selection_menu_pressed(self, event):
        row_count = self.data_model.getRowCount()
        for i in range(0, row_count):
            value = self.data_model.getValueAt(i, 0)
            self.data_model.setValueAt(not value, i, 0)

    def _update_all_rows(self, value):
        """This method updates the process column of all rows to value."""
        row_count = self.data_model.getRowCount()
        for i in range(0, row_count):
            self.data_model.setValueAt(value, i, 0)

    def _update_selected_rows(self, value):
        """This method updates the process column of all selected rows to value."""
        selected_rows = self.getSelectedRows()
        for selected_row in selected_rows:
            model_row = self.convertRowIndexToModel(selected_row)
            self.data_model.setValueAt(value, model_row, 0)
