# -*- coding: utf-8 -*-
"""
This module implements heatmap functionality.
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

import threading
from java.awt import Color
from java.lang import Float
from java.lang import Double
from java.lang import Integer
from javax.swing.table import DefaultTableCellRenderer


class PalletIndex:
    """
    This class manages the minimal and maximal values of a heat map group. In addition, it allows the computation of
    the index within the pallet list.
    """

    def __init__(self, min_value, max_value, column_names):
        if min_value == max_value:
            raise ValueError("Pallet values cannot be equal because this will lead to a division by zero exception.")
        self._value_lock = threading.Lock()
        self._min_value = min_value
        self._max_value = max_value
        self.column_names = column_names
        self._normalized_max_value = max_value - min_value

    def update_values(self, min_value, max_value):
        """
        Implementing a setter for min_value and max_value did not work. Therefore, we had to implement this workaround.
        :param min_value:
        :param max_value:
        :return:
        """
        if min_value == max_value:
            raise ValueError("Pallet values cannot be equal because this will lead to a division by zero exception.")
        with self._value_lock:
            self._min_value = min_value
            self._max_value = max_value
            self._normalized_max_value = max_value - min_value

    def update_value(self, current_value):
        """
        This method compares the given value against the current min and max values and if necessary updates them
        accordingly.
        :param current_value: The value against which min/max values are compared.
        :return: True if the min/max value was updated.
        """
        result = False
        if current_value < self._min_value:
            with self._value_lock:
                self._min_value = current_value
                self._normalized_max_value = self._max_value - self._min_value
            result = True
        elif self._max_value < current_value:
            with self._value_lock:
                self._max_value = current_value
                self._normalized_max_value = self._max_value - self._min_value
            result = True
        return result

    def get_pallet_index(self, pallet_length, value):
        """This method returns the index in the pallet for the given cell value."""
        with self._value_lock:
            if value < self._min_value:
                self._min_value = value
                self._normalized_max_value = self._max_value - self._min_value
            if value > self._max_value:
                self._max_value = value
                self._normalized_max_value = self._max_value - self._min_value
            i = pallet_length * (value - self._min_value) / self._normalized_max_value
        return int(min(max(i, 0), pallet_length - 1))

    def __repr__(self):
        return "({}/{}/{})".format(self._min_value, self._max_value, self._normalized_max_value)


class HeatMapMenuEntry:
    """
    This class implements a single heat map menu entry.
    """

    def __init__(self, column_name, class_type):
        self.column_name = column_name
        self.heat_map_groups = []
        if class_type == Float or class_type == float:
            self.class_type = Float
        elif class_type == Double:
            self.class_type = Double
        elif class_type == Integer or class_type == int:
            self.class_type = Integer
        else:
            raise NotImplementedError("Case not implemented")


class IntelTableCellRenderer(DefaultTableCellRenderer):
    """
    This class implements a heat map for the UI table.
    """

    def __init__(self, intel_table, pallet, pallet_indices):
        DefaultTableCellRenderer.__init__(self)
        self._intel_table = intel_table
        self._pallet = pallet
        self._pallet_length = len(self._pallet)
        self.pallet_indices_lock = threading.Lock()
        self.pallet_indices = pallet_indices
        self.pallet_indices_count = len(pallet_indices)

    def getTableCellRendererComponent(self, table, value, is_selected, has_focus, row, column):
        """This method is called by the UI table to calculate a row's background color."""
        result = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, is_selected, has_focus, row, column)
        with self.pallet_indices_lock:
            pallet_indices_count = self.pallet_indices_count
        if column < pallet_indices_count:
            with self.pallet_indices_lock:
                pallet_index = self.pallet_indices[column]
            if pallet_index:
                index = pallet_index.get_pallet_index(self._pallet_length, value)
                result.setBackground(self._pallet[index])
            elif not is_selected:
                result.setBackground(None)
        else:
            result.setBackground(None)
        return result

    def update_pallet_indices(self, value, column_index):
        """
        This method updates the min/max values of the PalletIndex object located at column_index.
        :param value: The value based on which the min/max values of the PalletIndex object shall be updated. Note that
        this method assumes that but does not check whether the given value is numeric.
        :param column_index: The value's column index, which determines the PalletIndex object.
        :return: True if the min/max values of PalletIndex object were updated.
        """
        result = False
        with self.pallet_indices_lock:
            if column_index < self.pallet_indices_count:
                pallet = self.pallet_indices[column_index]
                # Only if there is a PalletIndex object, then check whether the heat map's min/max values shall be
                # updated
                if pallet:
                    result = pallet.update_value(value)
            else:
                self.pallet_indices.append(None)
                self.pallet_indices_count += 1
        return result


class IntelDefaultTableCellRenderer(DefaultTableCellRenderer):
    """
    This class implements the default JTable background. This is necessary to ensure that the background stays the same
    independent from whether the heat map is active or not.
    """

    def __init__(self):
        DefaultTableCellRenderer.__init__(self)

    def getTableCellRendererComponent(self, table, value, is_selected, has_focus, row, column):
        """This method is called by the UI table to calculate a row's background color."""
        result = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, is_selected, has_focus, row, column)
        if not is_selected:
            result.setBackground(None)
        return result
