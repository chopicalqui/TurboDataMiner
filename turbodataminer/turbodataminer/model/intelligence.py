# -*- coding: utf-8 -*-
"""
This module implements the core functionality for JTable's data model.
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

from java.lang import Float
from java.lang import Boolean
from javax.swing.table import AbstractTableModel


class IntelDataModelEntry:
    """
    Represents a single row in the IntelDataModel class

    This class contains all information about a single table row.
    """

    def __init__(self, elements, message_info=None, message_infos={}):
        """
        :param elements: A list of items that were extracted from the request and/or response
        :param message_info: The IHttpRequestResponse from where the data elements were extracted
        :param message_infos: List of additional IHttpRequestResponse objects associated with the current row.
        """
        self._elements = []
        for item in elements:
            if isinstance(item, Integer) or \
                    isinstance(item, Float) or \
                    isinstance(item, Boolean) or \
                    isinstance(item, int) or \
                    isinstance(item, float) or \
                    isinstance(item, bool):
                self._elements.append(item)
            else:
                self._elements.append(unicode(item, encoding="utf-8", errors="ignore"))
        self._length = len(elements)
        self._message_info = message_info
        self._message_infos = message_infos

    @property
    def len(self):
        """Returns the number elements of the row"""
        return self._length

    @property
    def message_info(self):
        """Returns the IHttpRequestResponse object from which the information was extracted"""
        return self._message_info

    @property
    def message_infos(self):
        """Returns the list of additional IHttpRequestResponse objects that are associated with the row"""
        return self._message_infos

    @property
    def elements(self):
        """Returns the content of the row in form of a list"""
        return self._elements

    def get_value_at(self, i):
        """Returns the element at position i"""
        if i >= self._length:
            return None
        return self._elements[i]

    def get_type_at(self, i):
        """Returns the element type at position i"""
        return_value = String
        value = self.get_value_at(i)
        if isinstance(value, bool):
            return_value = Boolean
        elif isinstance(value, float):
            return_value = Float
        elif isinstance(value, int):
            return_value = Integer
        elif isinstance(value, time):
            return_value = Date
        return return_value


class IntelDataModel(AbstractTableModel):
    """
    The data model used by class IntelTable

    This class implements the data model to display information in the IntelTable. This class maintains a list of rows.
    Each row is represented by the class IntelDataModelEntry.
    """

    def __init__(self):
        self._header = []
        self._content = []
        self._column_count = 0
        self._row_count = 0

    def set_header(self, header, reset_column_count=False):
        """
        Method used to set the header of the data model
        :param header: List of header elements
        :return: Returns true
        """
        if not isinstance(header, list):
            raise ValueError("Variable 'header' must be a list!")

        self._header = header
        count = len(header)
        if self._column_count <= count:
            self._column_count = count
        elif reset_column_count:
            self._column_count = count
        self.fireTableStructureChanged()
        return True

    def get_header(self):
        return self._header

    def clear_data(self):
        if self._row_count != 0:
            self._content = []
            old_row_count = self._row_count
            self._row_count = 0
            self.fireTableRowsDeleted(0, old_row_count - 1)

    def add_rows(self, entries):
        """
        Method used to add a new row to the data model

        :param entries: A list of IntelDataModelEntries
        """
        if not isinstance(entries, list):
            raise ValueError("Variable 'entries' must be a list!")

        rows = 0
        for entry in entries:
            if self._column_count < entry.len:
                self._column_count = entry.len
                self.fireTableStructureChanged()
            self._content.append(entry)
            rows = rows + 1

        old_row_count = self._row_count
        self._row_count = self._row_count + rows
        if rows > 0:
            self.fireTableRowsInserted(old_row_count, self._row_count - 1)

    def delete_row(self, row_index):
        if row_index < self._row_count:
            del self._content[row_index]
            self._row_count = self._row_count - 1
            self.fireTableRowsDeleted(row_index, row_index)

    def get_message_info_at(self, row_index):
        """Returns the message info at row_index"""
        return self._content[row_index].message_info

    def get_message_infos_at(self, row_index):
        """Returns the message infos at row_index"""
        return self._content[row_index].message_infos

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
            return None
        except:
            print(traceback.format_exc())
            return None

    def getValueAt(self, row_index, column_index):
        """Returns the element at row row_index and column column_index"""
        try:
            row = self._content[row_index]
            if column_index < row.len:
                return row.get_value_at(column_index)
        except:
            print(traceback.format_exc())
        return None

    def getColumnClass(self, column_index):
        """Returns the column type at column_index"""
        try:
            if self._row_count >= 1:
                row = self._content[0]
                return row.get_type_at(column_index)
        except:
            print(traceback.format_exc())
        return String
