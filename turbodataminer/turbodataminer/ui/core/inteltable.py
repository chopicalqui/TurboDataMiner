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

import csv
import traceback
import threading
from javax.swing import JTable
from javax.swing import JMenuItem
from javax.swing import JPopupMenu
from javax.swing import JOptionPane
from burp import IMessageEditorController
from javax.swing.filechooser import FileNameExtensionFilter
from turbodataminer.ui.core.scripting import IdePane
from turbodataminer.ui.core.scripting import ErrorDialog


class IntelTable(JTable, IMessageEditorController):
    """
    The component shows the extracted information in the graphical user interface in a JTable.

    This class uses the data model implemented by the IntelDataModel class.
    """
    def __init__(self, intel_tab, data_model, table_model_lock):
        JTable.__init__(self, data_model)
        self._table_model_lock = table_model_lock
        self._intel_tab = intel_tab
        self._data_model = data_model
        self.setAutoCreateRowSorter(True)
        self._currently_selected_message_info = None
        # table pop menu
        self._popup_menu = JPopupMenu()
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
            self._ref = 1
            self._data_model.clear_data()

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
                ErrorDialog.Show(self._intel_tab.extender.parent, traceback.format_exc())
                traceback.print_exc(file=self._intel_tab.callbacks.getStderr())
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
                ErrorDialog.Show(self._intel_tab.extender.parent, traceback.format_exc())
                traceback.print_exc(file=self._intel_tab.callbacks.getStderr())

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
            ErrorDialog.Show(self._intel_tab.extender.parent, traceback.format_exc())
            traceback.print_exc(file=self._intel_tab.callbacks.getStderr())
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
            ErrorDialog.Show(self._intel_tab.extender.parent, traceback.format_exc())
            traceback.print_exc(file=self._intel_tab.callbacks.getStderr())

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
            ErrorDialog.Show(self._intel_tab.extender.parent, traceback.format_exc())
            traceback.print_exc(file=self._intel_tab.callbacks.getStderr())
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
            ErrorDialog.Show(self._intel_tab.extender.parent, traceback.format_exc())
            traceback.print_exc(file=self._intel_tab.callbacks.getStderr())
        self._setEnablePopupMenu(True)

    def copy_selected_column_values_menu_pressed(self, event):
        """This method is invoked when the copy column values menu is selected"""
        thread = threading.Thread(target=self._copy_selected_column_values_menu_pressed)
        thread.daemon = True
        thread.start()

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
            ErrorDialog.Show(self._intel_tab.extender.parent, traceback.format_exc())
            traceback.print_exc(file=self._intel_tab.callbacks.getStderr())
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
            ErrorDialog.Show(self._intel_tab.extender.parent, traceback.format_exc())
            traceback.print_exc(file=self._intel_tab.callbacks.getStderr())
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
            ErrorDialog.Show(self._intel_tab.extender.parent, traceback.format_exc())
            traceback.print_exc(file=self._intel_tab.callbacks.getStderr())
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
            ErrorDialog.Show(self._intel_tab.extender.parent, traceback.format_exc())
            traceback.print_exc(file=self._intel_tab.callbacks.getStderr())
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
            ErrorDialog.Show(self._intel_tab.extender.parent, traceback.format_exc())
            traceback.print_exc(file=self._intel_tab.callbacks.getStderr())
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
