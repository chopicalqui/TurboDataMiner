# -*- coding: utf-8 -*-
"""
This module implements the UI component to display the collected intelligence.
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

import re
import os
import csv
import traceback
import threading
from java.net import URL
from java.awt import Color
from java.awt import Toolkit
from javax.swing import JMenu
from javax.swing import JTable
from javax.swing import JMenuItem
from javax.swing import JPopupMenu
from javax.swing import JOptionPane
from javax.swing import TransferHandler
from javax.swing import JCheckBoxMenuItem
from javax.swing.event import PopupMenuListener
from javax.swing.table import DefaultTableCellRenderer
from java.lang import Float
from java.lang import Double
from java.lang import String
from java.lang import Integer
from burp import IMessageEditorController
from javax.swing.filechooser import FileNameExtensionFilter
from turbodataminer.ui.core.scripting import IdePane
from turbodataminer.ui.core.scripting import ErrorDialog


class PalletIndex:
    """
    This class manages the minimal and maximal values of a heat map group. In addition, it allows the computation of
    the index within the pallet list.
    """

    def __init__(self, min_value, max_value):
        self._value_lock = threading.Lock()
        self._min_value = min_value
        self._max_value = max_value
        self._normalized_max_value = max_value - min_value

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


class HeatMapMenu(dict):
    """
    This class implements all logic to interact with the heat map menu.
    """

    def __init__(self, intel_table):
        dict.__init__(self)
        self._pallet = self._make_pallet()
        self._intel_table = intel_table

    def add_entry(self, entry):
        """
        This method adds the given menu entry to the heat map menu dictionary.
        :param entry:
        :return:
        """
        if entry.class_type.__name__ not in self:
            self[entry.class_type.__name__] = {}
        if entry.column_name not in self[entry.class_type.__name__]:
            self[entry.class_type.__name__][entry.column_name] = entry

    def _make_pallet(self):
        """This method calculates all background colors for the heat map."""
        result = []
        n = 100
        hue = 1/float(3)
        for i in range(0, n):
            result.append(Color.getHSBColor(hue - ( i * hue / float(n)), 0.5, 1))
        return result

    def create_menu_entries(self, heat_map_menu_item, actionPerformed):
        """
        This method creates the heat map menu.
        :param heat_map_menu_item: The parent heat map menu.
        :param actionPerformed: The method that is triggered, when the user clicks on the menu.
        :return:
        """
        heat_map_menu_item.removeAll()
        # For create heat map groups
        for data_type, columns in self.items():
            group_count = len(columns.values())
            data_type_menu = JMenu(data_type)
            heat_map_menu_item.add(data_type_menu)
            for column_name, column_config in columns.items():
                column_name_menu = JMenu(column_name)
                data_type_menu.add(column_name_menu)
                # If the heat map groups do not exist, then we have to create it first.
                if not column_config.heat_map_groups:
                    column_config.heat_map_groups = [False] * group_count
                count = 1
                group_selected = True not in column_config.heat_map_groups
                for item in column_config.heat_map_groups:
                    item_title = "Heat Map Group {}".format(count)
                    heat_map_group_menu = JCheckBoxMenuItem(item_title, item, actionPerformed=actionPerformed)
                    column_name_menu.add(heat_map_group_menu)
                    count += 1

    def set_selected(self, heat_map_group_menu_item):
        """
        This method updates the heat map configuration based on the user's selection.
        :param heat_map_group_menu_item:
        :return: Returns the data type that was updated.
        """
        result = None
        group_name_title = heat_map_group_menu_item.getText()
        column_name_title = heat_map_group_menu_item.getParent().getInvoker().getText()
        data_type_title = heat_map_group_menu_item.getParent().getInvoker().getParent().getInvoker().getText()
        match_index = re.match("^.*?\s+(?P<value>\d+)$", group_name_title)
        if match_index:
            index = int(match_index.group("value"))
            settings = self[data_type_title][column_name_title]
            settings.heat_map_groups = [False] * len(settings.heat_map_groups)
            if heat_map_group_menu_item.isSelected():
                settings.heat_map_groups[index - 1] = True
        # Determine the data type that was updated. This is necessary to update the corresponding table cell renderer.
        if data_type_title == "Integer":
            result = Integer
        elif data_type_title == "Float":
            result = Float
        elif data_type_title == "Double":
            result = Double
        return result

    def get_table_cell_renderer(self, data_type):
        """
        Create the table cell renderer for the given data type.
        :param data_type:
        :return: IntelTableRenderer
        """
        group_names = {}
        # Create inventory of selected columns
        for column_name, settings in self[data_type.__name__].items():
            try:
                index = settings.heat_map_groups.index(True)
                if index not in group_names:
                    group_names[index] = {}
                group_names[index][column_name] = settings
            except ValueError:
                pass
        # Compile the pallet indices that is used by the table cell renderer
        column_count = self._intel_table.get_column_count()
        pallet_indices = [None] * column_count
        heat_map_active = False
        for group_index, column_names in group_names.items():
            # Obtain min and max values for the current heat map group
            column_names = [item for item in column_names.keys()]
            min_value, max_value = self._intel_table.get_min_max_values(column_names)
            if min_value != max_value:
                min_max_pair = PalletIndex(min_value, max_value)
                for i in range(0, column_count):
                    column_name = self._intel_table.get_column_name(i)
                    if column_name in column_names:
                        pallet_indices[i] = min_max_pair
                        heat_map_active = True
        # Create the correct table cell renderer
        if heat_map_active:
            result = IntelTableCellRenderer(self._intel_table, self._pallet, pallet_indices)
        else:
            result = IntelDefaultTableCellRenderer()
        return result


class IntelTableCellRenderer(DefaultTableCellRenderer):
    """
    This class implements a heat map for the UI table.
    """

    def __init__(self, intel_table, pallet, pallet_indices):
        DefaultTableCellRenderer.__init__(self)
        self._intel_table = intel_table
        self._pallet = pallet
        self._pallet_length = len(self._pallet)
        self._pallet_indices = pallet_indices

    def getTableCellRendererComponent(self, table, value, is_selected, has_focus, row, column):
        """This method is called by the UI table to calculate a row's background color."""
        result = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, is_selected, has_focus, row, column)
        pallet_index = self._pallet_indices[column]
        if pallet_index:
            index = pallet_index.get_pallet_index(self._pallet_length, value)
            result.setBackground(self._pallet[index])
        elif not is_selected:
            result.setBackground(None)
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


class IntelTablePopupMenuListener(PopupMenuListener):
    def __init__(self, intel_table):
        PopupMenuListener.__init__(self)
        self._intel_table = intel_table
        self._renderer = None
        self._heat_map_menu_info = None

    def popupMenuWillBecomeVisible(self, event):
        """
        This method is executed before the UI table's context menu is displayed.
        :param event:
        :return:
        """
        menu = event.getSource()
        menu_item_count = menu.getComponentCount()
        heat_map_item = None
        # Obtain heat map menu item
        for i in range(0, menu_item_count):
            item = menu.getComponent(i)
            if isinstance(item, JMenu) and item.getText() == "Heat Map":
                heat_map_item = item
        if heat_map_item:
            self._intel_table.load_head_map_menu_entries()
            self._intel_table.heat_map_menu.create_menu_entries(heat_map_item,
                                                                actionPerformed=self.action_checked_menu_item)

    def action_checked_menu_item(self, event):
        """
        This method is executed when a user clicks a heat map context menu entry.
        :param event:
        :return:
        """
        # Update user configuration
        data_type = self._intel_table.heat_map_menu.set_selected(event.getSource())
        if data_type:
            table_cell_renderer = self._intel_table.heat_map_menu.get_table_cell_renderer(data_type)
            self._intel_table.setDefaultRenderer(data_type, table_cell_renderer)
            self._intel_table.repaint()

    def refresh(self):
        pass

    def popupMenuCanceled(self, event):
        pass

    def popupMenuWillBecomeInvisible(self, event):
        pass


class IntelTable(JTable, IMessageEditorController):
    """
    The component shows the extracted information in the graphical user interface in a JTable.

    This class uses the data model implemented by the IntelDataModel class.
    """
    def __init__(self, intel_tab, data_model, table_model_lock):
        JTable.__init__(self, data_model)
        self.setDefaultRenderer(Integer, IntelDefaultTableCellRenderer())
        self.setDefaultRenderer(String, IntelDefaultTableCellRenderer())
        self.setDefaultRenderer(Float, IntelDefaultTableCellRenderer())
        self.setDefaultRenderer(Double, IntelDefaultTableCellRenderer())
        self._table_model_lock = table_model_lock
        self._intel_tab = intel_tab
        self._data_model = data_model
        self.heat_map_menu = HeatMapMenu(self)
        self.setAutoCreateRowSorter(True)
        self._currently_selected_message_info = None
        # table pop menu
        self._popup_menu = JPopupMenu()
        self._popup_menu.addPopupMenuListener(IntelTablePopupMenuListener(self))
        # Clear Table
        item = JMenuItem("Clear Table", actionPerformed=self.clear_table_menu_pressed)
        item.setToolTipText("Remove all rows from the table.")
        self._popup_menu.add(item)
        # Refresh Table
        item = JMenuItem("Refresh Table", actionPerformed=self.refresh_table_menu_pressed)
        item.setToolTipText("Synchronize the table with it's underlying data model.")
        self._popup_menu.add(item)
        self._popup_menu.addSeparator()
        # Export CSV
        item = JMenuItem("Export CSV", actionPerformed=self.export_csv_menu_pressed)
        item.setToolTipText("Export the content of the table to a CSV file.")
        self._popup_menu.add(item)
        self._popup_menu.addSeparator()
        # Copy Selected Row(s)
        item = JMenuItem("Copy Selected Row(s)", actionPerformed=self.copy_selected_values_menu_pressed)
        item.setToolTipText("Copy the selected rows into the clipboard. To obtain the content of the header row as "
                            "well, you can use menu item 'Copy Header Row'.")
        self._popup_menu.add(item)
        # Copy Header Row
        item = JMenuItem("Copy Header Row", actionPerformed=self.copy_header_row_menu_pressed)
        item.setToolTipText("You can use this menu item to copy and paste the table's header row. You can use this "
                            "function in combination with menu item 'Copy Selected Row(s)'.")
        self._popup_menu.add(item)
        # Copy Cell Value
        item = JMenuItem("Copy Cell Value", actionPerformed=self.copy_single_value_menu_pressed)
        item.setToolTipText("Copy the value of the cell on which you launched this menu item.")
        self._popup_menu.add(item)
        # Copy All Column Values
        item = JMenuItem("Copy All Column Values", actionPerformed=self.copy_all_column_values_menu_pressed)
        item.setToolTipText("Copy all values of the column on which you launched this menu item.")
        self._popup_menu.add(item)
        # Copy Selected Column Values
        item = JMenuItem("Copy Selected Column Values", actionPerformed=self.copy_selected_column_values_menu_pressed)
        item.setToolTipText("Copy the column values of all rows that are currently selected.")
        self._popup_menu.add(item)
        # Copy All Column Values (Deduplicated)
        item = JMenuItem("Copy All Column Values (Deduplicated)",
                         actionPerformed=self.copy_all_column_values_dedup_menu_pressed)
        item.setToolTipText("Like menu item 'Copy All Column Values' but only copies unique values into the clipboard.")
        self._popup_menu.add(item)
        # Copy Selected Column Values (Deduplicated)
        item = JMenuItem("Copy Selected Column Values (Deduplicated)",
                         actionPerformed=self.copy_selected_column_values_dedup_menu_pressed)
        item.setToolTipText("Like menu item 'Copy Selected Column Values' but only copies unique values into the "
                            "clipboard.")
        self._popup_menu.add(item)
        self._popup_menu.addSeparator()
        item = JMenu("Heat Map")
        item.setToolTipText("Creates a heat map on the selected column type(s).")
        self._popup_menu.add(item)
        self._popup_menu.addSeparator()
        # Delete Selected Row(s)
        item = JMenuItem("Delete Selected Row(s)", actionPerformed=self.delete_rows_menu_pressed)
        item.setToolTipText("Removes the selected rows from the table.")
        self._popup_menu.add(item)
        self._popup_menu.addSeparator()
        # Add Selected Host(s) To Scope
        item = JMenuItem("Add Selected Host(s) To Scope", actionPerformed=self.include_hosts_in_scope)
        item.setToolTipText("Include the host names of the selected requests in scope")
        self._popup_menu.add(item)
        # Remove Selected Host(s) From Scope
        item = JMenuItem("Remove Selected Host(s) From Scope", actionPerformed=self.exclude_hosts_from_scope)
        item.setToolTipText("Exclude the host names of the selected requests from scope")
        self._popup_menu.add(item)
        self._popup_menu.addSeparator()
        # Send Selected Row(s) to Repeater
        item = JMenuItem("Send Selected Row(s) to Repeater", actionPerformed=self.send_to_repeater)
        item.setToolTipText("Send the request of the selected row to Burp Suite's Repeater for further analysis.")
        self._popup_menu.add(item)
        self.setComponentPopupMenu(self._popup_menu)

    def _setEnablePopupMenu(self, enabled):
        for item in self._popup_menu.getSubElements():
            item.setEnabled(enabled)

    def refresh_table_menu_pressed(self, event):
        """This methed is invoked when the refresh table menu is selected"""
        with self._table_model_lock:
            self._data_model.fireTableStructureChanged()

    def clear_data(self):
        """Clears the table's content"""
        with self._table_model_lock:
            self.heat_map_menu = HeatMapMenu(self)
            self._data_model.clear_data()
            self.setDefaultRenderer(Integer, IntelDefaultTableCellRenderer())
            self.setDefaultRenderer(String, IntelDefaultTableCellRenderer())
            self.setDefaultRenderer(Float, IntelDefaultTableCellRenderer())
            self.setDefaultRenderer(Double, IntelDefaultTableCellRenderer())

    def clear_table_menu_pressed(self, event):
        """This method is invoked when the clear table menu is selected"""
        self.clear_data()

    def _export_csv_menu_pressed(self, file_name):
        """This method is invoked by a thread when the export CSV menu is selected"""
        if file_name:
            self._setEnablePopupMenu(False)
            try:
                with self._table_model_lock:
                    with open(file_name, 'wb') as csvfile:
                        csv_writer = csv.writer(csvfile, delimiter=";", quotechar='"', quoting=csv.QUOTE_MINIMAL)
                        # Write header
                        try:
                            header_row = [item.encode("ISO-8859-1") if item else "" for item in self._data_model.get_header()]
                            csv_writer.writerow(header_row)
                        except:
                            traceback.print_exc(file=self._intel_tab.callbacks.getStderr())
                        # Write content
                        for row_index in range(0, self._data_model.getRowCount()):
                            row = []
                            try:
                                for column_index in range(0, self._data_model.getColumnCount()):
                                    value = unicode(self._data_model.getValueAt(row_index, column_index)).encode("ISO-8859-1")
                                    row.append(value)
                            except:
                                traceback.print_exc(file=self._intel_tab.callbacks.getStderr())
                                row.append("error occured while exporting row")
                            csv_writer.writerow(row)
                JOptionPane.showConfirmDialog(self._intel_tab.extender.parent,
                                              "Exporting the CSV file completed successfully.",
                                              "Export completed ...",
                                              JOptionPane.DEFAULT_OPTION)
            except:
                traceback.print_exc(file=self._intel_tab.callbacks.getStderr())
                ErrorDialog.Show(self._intel_tab.extender.parent, traceback.format_exc())
            self._setEnablePopupMenu(True)

    def export_csv_menu_pressed(self, event):
        """This method is invoked when the export CSV menu is selected"""
        filter = FileNameExtensionFilter("CSV files", ["csv"])
        file_name = IdePane.open_file_chooser(self, filter)
        thread = threading.Thread(target=self._export_csv_menu_pressed, args=(file_name, ))
        thread.daemon = True
        thread.start()

    def copy_header_row_menu_pressed(self, event):
        """This method is invoked when the copy header row menu is selected"""
        header_row = self._data_model.get_header()
        if header_row:
            try:
                with self._table_model_lock:
                    self._intel_tab.ide_pane.copy_to_clipboard("\t".join(header_row))
                JOptionPane.showConfirmDialog(self._intel_tab.extender.parent,
                                              "Copying the header row to clipboard completed successfully.",
                                              "Copying completed ...",
                                              JOptionPane.DEFAULT_OPTION)
            except:
                traceback.print_exc(file=self._intel_tab.callbacks.getStderr())
                ErrorDialog.Show(self._intel_tab.extender.parent, traceback.format_exc())

    def _copy_selected_values_menu_pressed(self):
        """This helper method is invoked by a thread when the copy all menu is selected"""
        self._setEnablePopupMenu(False)
        try:
            with self._table_model_lock:
                clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
                self.getTransferHandler().exportToClipboard(self, clipboard, TransferHandler.COPY)
            JOptionPane.showConfirmDialog(self._intel_tab.extender.parent,
                                          "Copying the selected values to clipboard completed successfully.",
                                          "Copying completed ...",
                                          JOptionPane.DEFAULT_OPTION)
        except:
            traceback.print_exc(file=self._intel_tab.callbacks.getStderr())
            ErrorDialog.Show(self._intel_tab.extender.parent, traceback.format_exc())
        self._setEnablePopupMenu(True)

    def copy_selected_values_menu_pressed(self, event):
        """This method is invoked when the copy all menu is selected"""
        thread = threading.Thread(target=self._copy_selected_values_menu_pressed)
        thread.daemon = True
        thread.start()

    def _copy_column_values_as_list(self, column_index, selected_rows_only=False):
        """This method returns all values of the given column_index as list"""
        with self._table_model_lock:
            rows = [self.convertRowIndexToModel(selected_row) for selected_row in self.getSelectedRows()] \
                if selected_rows_only else range(0, self._data_model.getRowCount())
            items = [self._data_model.getValueAt(index, column_index) for index in rows]
        return items

    def _copy_column_values_as_dict(self, column_index, selected_rows_only=False):
        """This method returns all values of the given column_index as dict"""
        items = {}
        with self._table_model_lock:
            rows = [self.convertRowIndexToModel(selected_row) for selected_row in self.getSelectedRows()] \
                if selected_rows_only else range(0, self._data_model.getRowCount())
            for index in rows:
                item = self._data_model.getValueAt(index, column_index)
                if item in items:
                    items[item] = items[item] + 1
                else:
                    items[item] = 0
        return items

    def copy_single_value_menu_pressed(self, event):
        """This method is invoked when the copy single value menu is selected"""
        try:
            with self._table_model_lock:
                selected_column = self.getSelectedColumn()
                selected_row = self.getSelectedRow()
                model_row = self.convertRowIndexToModel(selected_row)
                value = self._data_model.getValueAt(model_row, selected_column)
                self._intel_tab.ide_pane.copy_to_clipboard(value)
            JOptionPane.showConfirmDialog(self._intel_tab.extender.parent,
                                          "Copying the selected cell value to clipboard completed successfully.",
                                          "Copying completed ...",
                                          JOptionPane.DEFAULT_OPTION)
        except:
            traceback.print_exc(file=self._intel_tab.callbacks.getStderr())
            ErrorDialog.Show(self._intel_tab.extender.parent, traceback.format_exc())

    def _copy_all_column_values_menu_pressed(self):
        """This helper method is invoked by a thread when the copy column values menu is selected"""
        self._setEnablePopupMenu(False)
        try:
            with self._table_model_lock:
                selected_column = self.getColumnModel().getSelectionModel().getLeadSelectionIndex()
                data = ""
                for item in self._copy_column_values_as_list(selected_column):
                    data += unicode(item) + os.linesep
                self._intel_tab.ide_pane.copy_to_clipboard(data)
            JOptionPane.showConfirmDialog(self._intel_tab.extender.parent,
                                          "Copying all column values to clipboard completed successfully.",
                                          "Copying completed ...",
                                          JOptionPane.DEFAULT_OPTION)
        except:
            traceback.print_exc(file=self._intel_tab.callbacks.getStderr())
            ErrorDialog.Show(self._intel_tab.extender.parent, traceback.format_exc())
        self._setEnablePopupMenu(True)

    def copy_all_column_values_menu_pressed(self, event):
        """This method is invoked when the copy column values menu is selected"""
        thread = threading.Thread(target=self._copy_all_column_values_menu_pressed)
        thread.daemon = True
        thread.start()

    def _copy_selected_column_values_menu_pressed(self):
        """This method is invoked by a thread when the copy column values menu is selected"""
        self._setEnablePopupMenu(False)
        try:
            with self._table_model_lock:
                selected_column = self.getColumnModel().getSelectionModel().getLeadSelectionIndex()
                data = ""
                for item in self._copy_column_values_as_list(selected_column, selected_rows_only=True):
                    data += unicode(item) + os.linesep
                self._intel_tab.ide_pane.copy_to_clipboard(data)
            JOptionPane.showConfirmDialog(self._intel_tab.extender.parent,
                                          "Copying the selected column values to clipboard completed successfully.",
                                          "Copying completed ...",
                                          JOptionPane.DEFAULT_OPTION)
        except:
            traceback.print_exc(file=self._intel_tab.callbacks.getStderr())
            ErrorDialog.Show(self._intel_tab.extender.parent, traceback.format_exc())
        self._setEnablePopupMenu(True)

    def copy_selected_column_values_menu_pressed(self, event):
        """This method is invoked when the copy column values menu is selected"""
        thread = threading.Thread(target=self._copy_selected_column_values_menu_pressed)
        thread.daemon = True
        thread.start()

    def load_head_map_menu_entries(self):
        with self._table_model_lock:
            count = self._data_model.getColumnCount()
            numeric_columns = 0
            # Setup menu structure as a dict
            for i in range(0, count):
                column_name = self._data_model.getColumnName(i)
                class_type = self._data_model.getColumnClass(i)
                if column_name and self._data_model.is_numeric(i):
                    menu_entry = HeatMapMenuEntry(column_name, class_type)
                    self.heat_map_menu.add_entry(menu_entry)

    def get_value_at(self, row_index, column_index):
        """Returns the element at row row_index and column column_index"""
        with self._table_model_lock:
            result = self._data_model.getValueAt(row_index, column_index)
        return result

    def get_column_name(self, column_index):
        """Returns true if the column type at column_index is numeric"""
        with self._table_model_lock:
            result = self._data_model.getColumnName(column_index)
        return result

    def get_column_count(self):
        """Returns the count of existing columns"""
        with self._table_model_lock:
            result = self._data_model.getColumnCount()
        return result

    def get_min_max_values(self, column_names):
        """
        Returns the smallest and largest value over the given volumn_names
        :param column_names: List of columns over which the smallest and largest value should be found
        :return: List with two elements. The first element contains the smallest and the second element the largest
        value
        """
        with self._table_model_lock:
            result = self._data_model.get_min_max_values(column_names)
        return result

    def _copy_all_column_values_dedup_menu_pressed(self):
        """This method is invoked by a thread when the copy column values deduplicated menu is selected"""
        self._setEnablePopupMenu(False)
        try:
            with self._table_model_lock:
                selected_column = self.getColumnModel().getSelectionModel().getLeadSelectionIndex()
                data = unicode("")
                for key, value in self._copy_column_values_as_dict(selected_column).items():
                    data += unicode(key) + os.linesep
                self._intel_tab.ide_pane.copy_to_clipboard(data)
            JOptionPane.showConfirmDialog(self._intel_tab.extender.parent,
                                          "Copying all deduplicated column values to clipboard completed "
                                          "successfully.",
                                          "Copying completed ...",
                                          JOptionPane.DEFAULT_OPTION)
        except:
            traceback.print_exc(file=self._intel_tab.callbacks.getStderr())
            ErrorDialog.Show(self._intel_tab.extender.parent, traceback.format_exc())
        self._setEnablePopupMenu(True)

    def copy_all_column_values_dedup_menu_pressed(self, event):
        """This method is invoked when the copy column values deduplicated menu is selected"""
        thread = threading.Thread(target=self._copy_all_column_values_dedup_menu_pressed)
        thread.daemon = True
        thread.start()

    def _copy_selected_column_values_dedup_menu_pressed(self):
        """This method is invoked by a thread when the copy column values deduplicated menu is selected"""
        self._setEnablePopupMenu(False)
        try:
            with self._table_model_lock:
                selected_column = self.getColumnModel().getSelectionModel().getLeadSelectionIndex()
                data = unicode("")
                for key, value in self._copy_column_values_as_dict(selected_column, selected_rows_only=True).items():
                    data += unicode(key) + os.linesep
                self._intel_tab.ide_pane.copy_to_clipboard(data)
            JOptionPane.showConfirmDialog(self._intel_tab.extender.parent,
                                          "Copying selected deduplicated column values to clipboard completed "
                                          "successfully.",
                                          "Copying completed ...",
                                          JOptionPane.DEFAULT_OPTION)
        except:
            traceback.print_exc(file=self._intel_tab.callbacks.getStderr())
            ErrorDialog.Show(self._intel_tab.extender.parent, traceback.format_exc())
        self._setEnablePopupMenu(True)

    def copy_selected_column_values_dedup_menu_pressed(self, event):
        """This method is invoked when the copy column values deduplicated menu is selected"""
        thread = threading.Thread(target=self._copy_selected_column_values_dedup_menu_pressed)
        thread.daemon = True
        thread.start()

    def _delete_rows_menu_pressed(self):
        """This method is invoked by a thread when the delete rows button is pressed"""
        self._setEnablePopupMenu(False)
        try:
            with self._table_model_lock:
                selected_rows = self.getSelectedRows()
                rows = []
                for selected_row in selected_rows:
                    model_row = self.convertRowIndexToModel(selected_row)
                    rows.append(model_row)
                rows.sort(reverse=True)
                for i in rows:
                    self._data_model.delete_row(i)
            JOptionPane.showConfirmDialog(self._intel_tab.extender.parent,
                                          "Deleting the selected rows completed successfully.",
                                          "Deleting completed ...",
                                          JOptionPane.DEFAULT_OPTION)
        except:
            traceback.print_exc(file=self._intel_tab.callbacks.getStderr())
            ErrorDialog.Show(self._intel_tab.extender.parent, traceback.format_exc())
        self._setEnablePopupMenu(True)

    def delete_rows_menu_pressed(self, event):
        """This method is invoked when the delete rows button is pressed"""
        thread = threading.Thread(target=self._delete_rows_menu_pressed)
        thread.daemon = True
        thread.start()

    def _add_remove_scope(self, in_scope):
        """If true, then adds the given URL to scope, else the URL is excluded from scope"""
        self._setEnablePopupMenu(False)
        try:
            with self._table_model_lock:
                dedup = {}
                selected_rows = self.getSelectedRows()
                for selected_row in selected_rows:
                    model_row = self.convertRowIndexToModel(selected_row)
                    message_info = self._data_model.get_message_info_at(model_row)
                    if message_info:
                        http_service = message_info.getHttpService()
                        url = URL(http_service.getProtocol(), http_service.getHost(), http_service.getPort(), "")
                        if unicode(url) not in dedup:
                            if in_scope:
                                if not self._intel_tab.callbacks.isInScope(url):
                                    self._intel_tab.callbacks.includeInScope(url)
                            else:
                                self._intel_tab.callbacks.excludeFromScope(url)
                            dedup[unicode(url)] = None
            if in_scope:
                JOptionPane.showConfirmDialog(self._intel_tab.extender.parent,
                                              "Adding selected host name(s) in scope completed successfully.",
                                              "Adding in scope completed ...",
                                              JOptionPane.DEFAULT_OPTION)
            else:
                JOptionPane.showConfirmDialog(self._intel_tab.extender.parent,
                                              "Deleting selected host name(s) from scope completed successfully.",
                                              "Deleting from scope completed ...",
                                              JOptionPane.DEFAULT_OPTION)
        except:
            traceback.print_exc(file=self._intel_tab.callbacks.getStderr())
            ErrorDialog.Show(self._intel_tab.extender.parent, traceback.format_exc())
        self._setEnablePopupMenu(True)

    def include_hosts_in_scope(self, event):
        """Adds the currently selected hosts in scope"""
        thread = threading.Thread(target=self._add_remove_scope, args=(True, ))
        thread.daemon = True
        thread.start()

    def exclude_hosts_from_scope(self, event):
        """Excludes the currently selected hosts from scope"""
        thread = threading.Thread(target=self._add_remove_scope, args=(False, ))
        thread.daemon = True
        thread.start()

    def _sent_to_burp_function(self, function):
        """This method sends the selected request to the given callback function (e.g., callbacks.sendToIntruder)"""
        self._setEnablePopupMenu(False)
        try:
            with self._table_model_lock:
                selected_rows = self.getSelectedRows()
                id = 1
                for selected_row in selected_rows:
                    model_row = self.convertRowIndexToModel(selected_row)
                    message_info = self._data_model.get_message_info_at(model_row)
                    if message_info:
                        http_service = message_info.getHttpService()
                        use_https = http_service.getProtocol().lower() == "https"
                        function(http_service.getHost(),
                                 http_service.getPort(),
                                 use_https,
                                 message_info.getRequest(),
                                 "Turbo Miner {}".format(id))
                    id += 1
            JOptionPane.showConfirmDialog(self._intel_tab.extender.parent,
                                          "Sending selected items to Repeater completed successfully.",
                                          "Sending completed ...",
                                          JOptionPane.DEFAULT_OPTION)
        except:
            traceback.print_exc(file=self._intel_tab.callbacks.getStderr())
            ErrorDialog.Show(self._intel_tab.extender.parent, traceback.format_exc())
        self._setEnablePopupMenu(True)

    def send_to_repeater(self, event):
        """Sends the currently selected requests to the Repeater"""
        thread = threading.Thread(target=self._sent_to_burp_function, args=(self._intel_tab.callbacks.sendToRepeater, ))
        thread.daemon = True
        thread.start()

    def getHttpService(self):
        """Returns the burp.IHttpService object of the currently selected message info"""
        return self._currently_selected_message_info.getHttpService()

    def getRequest(self):
        """Returns the burp.IRequestInfo object of the currently selected message info"""
        return self._currently_selected_message_info.getRequest()

    def getResponse(self):
        """Returns the burp.IResponseInfo object of the currently selected message info"""
        return self._currently_selected_message_info.getRequest()

    def changeSelection(self, row, col, toggle, extend):
        """This method is invoked when a table row is selected. It then refreshes the details in the message tabs."""
        # show the log entry for the selected row
        if self._intel_tab:
            with self._table_model_lock:
                model_row = self.convertRowIndexToModel(row)
                self._currently_selected_message_info = self._data_model.get_message_info_at(model_row)
                self._intel_tab.work_tab_pane.message_infos = self._data_model.get_message_infos_at(model_row)
                self._intel_tab.message_info_pane.set_message_info(self._currently_selected_message_info)
                JTable.changeSelection(self, row, col, toggle, extend)
