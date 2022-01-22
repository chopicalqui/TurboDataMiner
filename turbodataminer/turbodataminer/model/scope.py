# -*- coding: utf-8 -*-
"""
This module implements the functionality to provide better scoping capabilities.
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

import time
import traceback
from java.lang import Float
from java.lang import String
from java.lang import Integer
from java.lang import Boolean
from javax.swing.table import AbstractTableModel


class BaseScopeDataModel(AbstractTableModel):
    """
    The data model used by class ScopeTable

    This class implements the data model to display scope information in the ScopeTable. This class maintains a list
    of rows.
    """

    def __init__(self, header=[], content=[]):
        self._header = ["Process"]
        self._header += header
        self._content = []
        for item in content:
            row = [False]
            row += list(item)
            self._content.append(row)
        self._column_count = len(self._header)
        self._row_count = len(self._content)
        self.fireTableStructureChanged()
        if self._row_count > 0:
            self.fireTableRowsInserted(0, self._row_count - 1)

    def set_header(self, columns):
        self._header = ["Process"]
        self._header += columns
        self._column_count = len(self._header)
        self.fireTableStructureChanged()

    def set_content(self, rows):
        self._content = []
        for item in rows:
            row = [False]
            row += list(item)
            self._content.append(row)
        self._row_count = len(self._content)
        if self._row_count > 0:
            self.fireTableRowsInserted(0, self._row_count - 1)

    def getRowCount(self):
        """Returns the total number of rows managed by the data model"""
        try:
            return self._row_count
        except:
            print(traceback.format_exc())
            return 0

    def getColumnCount(self):
        """Returns the total number of columns managemed by the data model"""
        try:
            return self._column_count
        except:
            print(traceback.format_exc())
            return 0

    def getColumnName(self, column_index):
        """Returns the column name at position column_index"""
        try:
            if column_index < len(self._header):
                return self._header[column_index]
        except:
            print(traceback.format_exc())
        return None

    def getValueAt(self, row_index, column_index):
        """Returns the element at row row_index and column column_index"""
        return self._content[row_index][column_index]

    def isCellEditable(self, row_index, column_index):
        """Returns true if the cell is editable."""
        return column_index == 0

    def setValueAt(self, value, row_index, column_index):
        """Updates the value at the given position"""
        self._content[row_index][column_index] = value
        self.fireTableCellUpdated(row_index, column_index)

    def get_type_at(self, column_index):
        """Returns the element type at position i"""
        result = String
        if self._row_count >= 1:
            value = self._content[0][column_index]
            if isinstance(value, bool):
                result = Boolean
            elif isinstance(value, float):
                result = Float
            elif isinstance(value, int):
                result = Integer
            elif isinstance(value, time):
                result = Date
        return result

    def getColumnClass(self, column_index):
        """Returns the column type at column_index"""
        return self.get_type_at(column_index)
