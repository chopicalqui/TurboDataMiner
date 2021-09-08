# -*- coding: utf-8 -*-
"""
The objective of this Burp Suite extension is the flexible and dynamic extraction, correlation, and structured
presentation of information from the Burp Suite project as well as the flexible and dynamic on-the-fly modification
of outgoing or incoming HTTP requests using Python scripts. Thus, Turbo Data Miner shall aid in gaining a better and
faster understanding of the data collected by Burp Suite.
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
import os
import csv
import uuid
import threading
import time
import re
import base64
import HTMLParser
import json
import sys
from burp import IBurpExtender
from burp import ITab
from burp import IHttpListener
from burp import IProxyListener
from burp import IMessageEditorController
from burp import IExtensionStateListener
from burp import IContextMenuInvocation
from burp import IContextMenuFactory
from burp import IBurpExtenderCallbacks
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import IParameter
from burp import IRequestInfo
from burp import IResponseInfo
from burp import IHttpRequestResponse
from javax.swing.table import AbstractTableModel
from threading import Lock
from threading import RLock
from javax.swing import JScrollPane
from javax.swing import JSplitPane
from javax.swing import JTabbedPane
from javax.swing import JTable
from javax.swing import JButton
from javax.swing import JFrame
from javax.swing import JDialog
from javax.swing import JPanel
from javax.swing import JTextArea
from javax.swing import JComboBox
from javax.swing import JToggleButton
from javax.swing import JPopupMenu
from javax.swing import JMenuItem
from javax.swing import JTextPane
from javax.swing import JFileChooser
from javax.swing import TransferHandler
from javax.swing import JLabel
from javax.swing import JOptionPane
from javax.swing import JTextField
from javax.swing import JList
from javax.swing.filechooser import FileNameExtensionFilter
from javax.swing.event import DocumentListener
from javax.swing import DefaultComboBoxModel
from javax.swing import SwingUtilities
from javax.swing.event import HyperlinkEvent;
from java.awt import BorderLayout
from java.awt import GridLayout
from java.awt import Font
from java.awt import Toolkit
from java.awt import Desktop
from java.awt.datatransfer import StringSelection
from java.lang import Integer
from java.lang import String
from java.lang import Float
from java.lang import Thread
from java.util import Date
from java.lang import Boolean
from java.net import URL
from java.net import URLClassLoader
from java.io import ByteArrayInputStream
from java.io import ByteArrayOutputStream
from java.io import InputStreamReader
from java.io import BufferedReader
from java.util.zip import GZIPInputStream
from java.util.zip import GZIPOutputStream


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


class IntelTable(JTable, IMessageEditorController):
    """
    The component that shows the extracted information in the graphical user interface in a JTable.

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


class ErrorDialog(JDialog):
    """
    This frame is shown if the Python script code entered in the IdePane cannot be compiled or raises an
    error/exception
    """
    def __init__(self, owner, exception):
        JFrame.__init__(self, owner, "Compile error", size=(800, 400))
        self._exception = exception
        text_area = JTextArea()
        text_area.setText(exception)
        text_area.setEditable(False)
        self.add(JScrollPane(text_area))

    @staticmethod
    def Show(owner, message):
        ef = ErrorDialog(owner, message)
        ef.setVisible(True)


class ScriptInformation:
    """
    This class holds all information and methods about a script
    """

    def __init__(self, guid=str(uuid.uuid4()), name=None, author=None, version=None, plugins=[], script=None):
        self._uuid = guid
        self._name = name
        self._author = author
        self._version = version
        self._plugins = plugins
        self._script = script

    @property
    def uuid(self):
        return self._uuid

    @uuid.setter
    def uuid(self, value):
        self._uuid = value

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def author(self):
        return self._author

    @author.setter
    def author(self, value):
        self._author = value

    @property
    def script(self):
        return self._script

    @script.setter
    def script(self, value):
        self._script = value

    @property
    def version(self):
        return self._version

    @version.setter
    def version(self, value):
        self._version = value

    @property
    def plugins(self):
        return self._plugins

    @plugins.setter
    def plugins(self, value):
        self._plugins = value

    @staticmethod
    def load_json(object):
        """This method parses the given json object and returns a class of type ScriptInformation"""
        json_object = json.JSONDecoder().decode(object) if isinstance(object, str) else object
        plugins = []
        if "plugins" in json_object:
            plugins = [IntelBase.get_plugin_by_id(plugin_id) for plugin_id in json_object["plugins"]]
        return ScriptInformation(json_object["uuid"] if "uuid" in json_object else None,
                                 json_object["name"] if "name" in json_object else None,
                                 json_object["author"] if "author" in json_object else None,
                                 json_object["version"] if "version" in json_object else None,
                                 plugins,
                                 json_object["script"] if "script" in json_object else None)

    def get_json(self):
        """This method returns a json object representing the object"""
        return {"uuid": self._uuid,
                "name": self._name,
                "author": self._author,
                "version": self._version,
                "plugins": [item.plugin_id for item in self._plugins],
                "script": self._script if self._script else ""}

    def __repr__(self):
        if self._name:
            return "{} ({}) - {} - {} - {}".format(self._name, self._uuid, self._version, self._author, self._plugins)
        return ""


class PluginInformation:
    """
    This plugin holds information about a specific plugin (e.g., Proxy History Parser)
    """
    def __init__(self, plugin_id, name, category, selected=False):
        self._plugin_id = plugin_id
        self._name = name
        self._selected = selected
        self._category = category

    @property
    def plugin_id(self):
        return self._plugin_id

    @property
    def name(self):
        return self._name

    @property
    def selected(self):
        return self._selected

    @property
    def category(self):
        return self._category

    def __repr__(self):
        return self._name


class SaveDialog(JDialog):
    """
    This dialog implements all functionality to save a new or update an existing script.
    """
    def __init__(self, owner,  plugin_category, script_info=ScriptInformation()):
        JDialog.__init__(self, owner, "Save Script", size=(800, 400))
        if script_info.uuid:
            self._script_info = script_info
        else:
            self._script_info = ScriptInformation(name=script_info.name,
                                                  author=script_info.author,
                                                  version=script_info.version,
                                                  plugins=script_info.plugins,
                                                  script=script_info.script)
        self.setLayout(GridLayout(1, 1))
        self.setModal(True)
        self._canceled = None
        self.windowClosing = self.cancel_action

        main_panel = JPanel()
        main_panel.setLayout(GridLayout(5,2))
        self.add(main_panel)
        self._plugins = IntelBase.get_plugins_by_category(plugin_category)
        self._select_plugins = JList(self._plugins)
        self._select_plugins.setToolTipText("Select the plugins in which this script will show up.")
        indices = []
        for plugin in script_info.plugins:
            self._select_plugins.setSelectedValue(plugin, True)
            index = self._select_plugins.getSelectedIndex()
            indices.append(index)
        self._select_plugins.setSelectedIndices(indices)
        self.add(self._select_plugins)

        l_guid = JLabel("GUID (Filename)")
        tf_guid = JTextField()
        tf_guid.setText(self._script_info.uuid)
        tf_guid.setEditable(False)
        tf_guid.setToolTipText("The unique ID and internal file name of this script.")
        main_panel.add(l_guid)
        main_panel.add(tf_guid)

        l_name = JLabel("Name")
        self._tf_name = JTextField()
        self._tf_name.setToolTipText("Insert a short description for the script.")
        self._tf_name.setText(self._script_info.name)
        main_panel.add(l_name)
        main_panel.add(self._tf_name)

        l_author = JLabel("Author")
        self._ta_author = JTextField()
        self._ta_author.setToolTipText("This field usually contains your name.")
        self._ta_author.setText(self._script_info.author)
        main_panel.add(l_author)
        main_panel.add(JScrollPane(self._ta_author))

        l_version = JLabel("Version")
        self._ta_version = JTextField()
        self._ta_version.setText(self._script_info.version)
        self._ta_version.setToolTipText("This script's current version.")
        main_panel.add(l_version)
        main_panel.add(JScrollPane(self._ta_version))

        b_save = JButton("Save", actionPerformed=self.save_action)
        main_panel.add(b_save)
        b_cancel = JButton("Cancel", actionPerformed=self.cancel_action)
        main_panel.add(b_cancel)

    def save_action(self, event):
        """
        This method is invoked when the save button is clicked.
        """
        name = self._tf_name.getText()
        version = self._ta_version.getText()
        author = self._ta_author.getText()
        selections = self._select_plugins.getSelectedIndices()
        if not name:
            JOptionPane.showMessageDialog(self,
                                          "The script must have a name!",
                                          "Missing Name",
                                          JOptionPane.ERROR_MESSAGE)
            return
        if not author:
            JOptionPane.showMessageDialog(self,
                                          "The script must have an author!",
                                          "Missing Author",
                                          JOptionPane.ERROR_MESSAGE)
            return
        if not version:
            JOptionPane.showMessageDialog(self,
                                          "The script must have a version!",
                                          "Missing Version",
                                          JOptionPane.ERROR_MESSAGE)
            return
        if len(selections) <= 0:
            JOptionPane.showMessageDialog(self,
                                          "This script must be assigned to at least one plugin!",
                                          "Missing Plugin",
                                          JOptionPane.ERROR_MESSAGE)
            return
        self._script_info._plugins = [self._plugins[index] for index in selections]
        self._script_info._name = name
        self._script_info._author = author
        self._script_info._version = version
        self._canceled = False
        self.setVisible(False)

    def cancel_action(self, event):
        """
        This method is invoked when the cancel button is clicked.
        """
        self._canceled = True
        self.setVisible(False)

    @property
    def canceled(self):
        return self._canceled


class ExportedMethods:
    """
    This class implements Turbo Data Miner's API
    """

    def __init__(self, extender, ide_pane):
        self._extender = extender
        self._ide_pane = ide_pane
        self._html_parser = HTMLParser.HTMLParser()
        self._signatures = {}
        self._extensions = {}
        self._vulners_rules = {}
        self.top_level_domains = []
        self.re_domain_name = \
            re.compile("(?P<domain>(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9])\.?")
        with open(os.path.join(extender.home_dir, "data/top-level-domains.json"), "r") as f:
            json_object = json.loads(f.read())
            self.top_level_domains = json_object["data"] if "data" in json_object else []
        with open(os.path.join(extender.home_dir, "data/file-signatures.json"), "r") as f:
            self._signatures = eval(f.read())
        with open(os.path.join(extender.home_dir, "data/file-extensions.json"), "r") as f:
            self._extensions = eval(f.read())
        with open(os.path.join(extender.home_dir, "data/version-vulns.json"), "r") as f:
            self._vulners_rules = eval(f.read())
            for name, details in self._vulners_rules["data"]["rules"].items():
                try:
                    details["regex"] = re.compile("{}".format(details["regex"]))
                except:
                    self._extender.callbacks.printError("Failed to compile regex while loading "
                                                        "software version database: {0}".format(details["regex"]))

    def _decode_jwt(self, item):
        result = json.dumps(item)
        result = result.replace('_', '/')
        result = result.replace('-', '+')
        result += '=' * (4 - len(unicode(result)) % 4)
        result = self._extender.helpers.bytesToString(self._extender.helpers.base64Decode(result))
        return result

    def _encode_jwt(self, item):
        result = self._extender.helpers.bytesToString(self._extender.helpers.base64Encode(item))
        result = result.split("=")[0]
        result = result.replace('+', '-')
        result = result.replace('/', '_')
        return result

    @staticmethod
    def _parse_json(content, attributes, must_match):
        """Recursion used by method parse_json"""
        rvalue = []
        if isinstance(content, dict):
            for key, value in content.items():
                rvalue.extend(ExportedMethods._parse_json(value, attributes, must_match))
            matches = 0
            tmp = attributes.copy()
            for item, __ in attributes.items():
                if item in content:
                    tmp[item] = content[item]
                    matches = matches + 1
            if (matches and must_match <= 0) or matches >= must_match:
                rvalue.append(tmp)
        elif isinstance(content, list):
            for item in content:
                rvalue.extend(ExportedMethods._parse_json(item, attributes, must_match))
        return rvalue

    @staticmethod
    def _get_dict(keys, value=None):
        rvalue = {}
        for key in keys:
            rvalue[key] = value
        return rvalue

    @staticmethod
    def _split_items(string, delimiter="="):
        pair = string.split(delimiter)
        if len(pair) == 1:
            return (string, None)
        elif len(pair) > 1:
            key_name = pair[0]
            value = delimiter.join(pair[1:])
            return (key_name, value)
        else:
            return (None, None)

    @staticmethod
    def _get_ascii(string, replace_char=".", replace_dict={}):
        rvalue = ""
        for char in string:
            i = char if isinstance(char, int) else ord(char)
            if char in replace_dict:
                rvalue = rvalue + replace_char[char]
            elif 33 <= i <= 126:
                rvalue = rvalue + (chr(i) if 33 <= i <= 126 else replace_char)
        return rvalue

    def analyze_request(self, message_info):
        """
        This method returns an IRequestInfo object based on the given IHttpRequestResponse object.

        :param message_info (IHttpRequestResponse): The IHttpRequestResponse whose request should be returned as an
        IRequestInfo object.
        :return (IRequestInfo): An IRequestInfo object or None, if no request was found.
        """
        request = message_info.getRequest()
        if request:
            result = self._extender.helpers.analyzeRequest(request)
        else:
            result = None
        return result

    def analyze_response(self, message_info):
        """
        This method returns an IResponseInfo object based on the given IHttpRequestResponse object.

        :param message_info (IHttpRequestResponse): The IHttpRequestResponse whose request should be returned as an
        IResponseInfo object.
        :return (IResponseInfo): An IResponseInfo object or None, if no response was found.
        """
        response = message_info.getResponse()
        if response:
            result = self._extender.helpers.analyzeResponse(response)
        else:
            result = None
        return result

    def analyze_signatures(self, content, strict=False):
        """
        This method checks whether the given string matches one of the known file signatures based on an internal
        database.

        :param content (str): The string that is tested for known file signatures.
        :param strict (bool): Bool which specifies whether the file signatures can appear anywhere within the given
        string (False) or at the expected position (True). Set this parameter to False (default) if you, for example,
        want to determine, whether a request or response might contain a file somewhere. Note that this might return an
        increased number of false positives.
        :return (List[Dict[str, object]]: List of dictionaries. Each dictionary contains the following keys that specify
        information about the matched file signature: extensions (List[str]), category (str), description (str),
        offset (int), hex_signatures (str), str_signatures (list), b64_signatures (list)
        """
        result = []
        for signatures in self._signatures["signatures"]:
            if not self._ide_pane.activated:
                return result
            for signature in signatures["hex_signatures"]:
                tmp = "^" + ("." * signatures["offset"]) + signature if strict else signature
                if re.search(tmp, content):
                    result.append(signatures)
            for signature in signatures["b64_signatures"]:
                tmp = "^" + ("." * signatures["offset"]) + signature if strict else signature
                if re.search(tmp, content):
                    result.append(signatures)
        return result

    def compress_gzip(self, content):
        """
        This method compresses the given string using GZIP and returns the compressed byte array. Note that this
        method might throw an exception.

        :param content (str): The string that shall be GZIP compressed.
        :return (List[bytes]): Byte array containing the GZIP compressed string.
        """
        output_stream = ByteArrayOutputStream()
        gzip_output_stream = GZIPOutputStream(output_stream)
        gzip_output_stream.write(content)
        gzip_output_stream.flush()
        gzip_output_stream.close()
        output_stream.close()
        return output_stream.toByteArray()

    def decode_jwt(self, jwt):
        """
        This method decodes the given JSON Web Token (JWT) and returns a triple containing the JWT header, JWT payload,
        and JWT signature.

        :param jwt (str): String containing the JWT.
        :return (List[str]): List with three string elements. The first element contains the header (or None), the
        second element the payload (or None), and the third element the signature (or None) of the JWT.
        """
        return_value = [None, None, None]
        jwt_re = re.compile("^(?P<header>eyJ[a-zA-Z0-9]+?)\.(?P<payload>eyJ[a-zA-Z0-9]+?)\.(?P<signature>[a-zA-Z0-9_\-=]+?)$")
        jwt_match = jwt_re.match(jwt)
        if jwt_match:
            header = jwt_match.group("header")
            payload = jwt_match.group("payload")
            signature = jwt_match.group("signature")
            header = self._decode_jwt(header)
            payload = self._decode_jwt(payload)
            return_value = [header, payload, signature]
        return return_value

    def decompress_gzip(self, content):
        """
        This method decompresses the given GZIP compressed byte array.

        :param content (list[bytes]): The byte array whose content shall be decompressed.
        :return (str): Decompresed string.
        :raise ZipException: If a GZIP format error has occurred or the compression method used is unsupported.
        :raise IOException: if an I/O error has occurred.
        """
        result = ""
        input_stream = ByteArrayInputStream(content)
        gzip_input_stream = GZIPInputStream(input_stream)
        input_stream_reader = InputStreamReader(gzip_input_stream)
        buffered_reader = BufferedReader(input_stream_reader)
        while buffered_reader.ready():
            result += buffered_reader.readLine()
        return result

    def decode_html(self, content):
        """
        This method can be used to HTML decode the given string.
        :param content (str): Value that shall be HTML decoded.
        :return (str): The HTML decoded version of the provided value.
        """
        return self._html_parser.unescape(content)

    def encode_jwt(self, header, payload, signature=None):
        """
        This method encodes the given JSON Web Token (JWT) header, JWT payload, and JWT signature into a complete JWT
        string.

        :param header (str): The dictionary containing the JWT header information.
        :param payload (str): The dictionary containing the JWT payload information.
        :param signature (str): The JWT's signature.
        :return (str): The final JWT string.
        """
        header_encoded = self._encode_jwt(header)
        payload_encoded = self._encode_jwt(payload)
        return "{}.{}.{}".format(header_encoded,
                                 payload_encoded,
                                 signature if signature else "")

    def find_domains(self, content):
        """
        This method searches the given text for valid host and domain names.

        The search is based on a regular expression and in order to decrease the likelihood of false positives, each
        identified identified domains top-level domain (TLD) is compared to a known list of TLDs.

        :param content (str): The string in which the domain names are searched.
        :return (List[str[): List of identified domain names.
        """
        result = []
        if not content:
            return result
        for item in self.re_domain_name.finditer(content):
            if not self._ide_pane.activated:
                return result
            domain_name = item.group("domain").lower()
            tld = domain_name.split(".")[-1]
            if tld in self.top_level_domains:
                result.append(domain_name)
        return result

    def find_versions(self, content):
        """
        This method searches the given text for known software versions based on an internal database
        (source: vulners.com).

        :param content: The string in which the software versions are searched.
        :return (List[Dict[str, str]]): List of dictionaries containing details about the identified software versions.
        each dictionary contains the following keys: software, type, version, cpe, alias, source
        """
        result = []
        for name, details in self._vulners_rules["data"]["rules"].items():
            if not self._ide_pane.activated:
                return result
            match = details["regex"].search(content)
            if match:
                item = {}
                item["software"] = name
                item["type"] = details["type"]
                item["version"] = match.group(1)
                item["cpe"] = "{}:{}".format(details["alias"], item["version"]) if item["type"] == "cpe" else None
                item["alias"] = details["alias"]
                item["source"] = self._vulners_rules["source"]
                result.append(item)
        return result

    def get_content_length(self, headers):
        """
        This method returns the first occurrence of the Content-Length from the given list of headers.

        :param headers (List[str]): The list of headers that shall be searched for the first occurrence of the
        Content-Length header. Usually, the list of headers is obtained via the getHeaders method implemented by
        Burp Suite's IRequestInfo or IResponseInfo interfaces.
        :return (int): Integer containing the content of the Content-Type header or None if it does not exist.
        """
        result = None
        re_cl = re.compile("^Content-Length:\s*(?P<length>\d+)\s*$", re.IGNORECASE)
        for header in headers:
            if not self._ide_pane.activated:
                return result
            match = re_cl.match(header)
            if match:
                result = int(match.group("length"))
                break
        return result

    def get_content_type(self, headers):
        """
        This method returns the first occurrence of the Content-Type from the given list of headers.

        :param headers (List[str]): The list of headers that shall be searched for the first occurrence of the
        Content-Type header. Usually, the list of headers is obtained via the getHeaders method implemented by
        Burp Suite's IRequestInfo or IResponseInfo interfaces.
        :return (str): String containing the content of the Content-Type header or None if it does not exist.
        """
        result = None
        re_ct = re.compile("^Content-Type:\s*(?P<type>.*?)(\s*;\s*.*)?$", re.IGNORECASE)
        for header in headers:
            if not self._ide_pane.activated:
                return result
            match = re_ct.match(header)
            if match:
                result = match.group("type")
                break
        return unicode(result, errors="ignore")

    def get_cookie_attributes(self):
        """
        This method returns a static list of all possible cookie attributes. This list can be used in combination with
        API method get_cookies to convert all obtained cookies from a dictionary into a list/table format.
        :return (List[str]): Static string list containing the following elements: name, value, expires, max-age,
        domain, path, secure, httponly, samesite
        """
        return ["name", "value", "expires", "max-age", "domain", "path", "secure", "httponly", "samesite"]

    def get_cookies(self, item, filter=[]):
        """
        This method takes an IResponseInfo or IRequestInfo object as the first argument and extracts all its cookie
        information. The second optional argument acts as a filtering option that limits the cookies to be extracted.

        :param item (IRequestInfo/IResponseInfo): The IRequestInfo or IResponseInfo item whose session information
        :param filter (List[str]): List of cookie names whose attributes shall be extracted and returned.
        :return (List[Dict[str, str]]): The method returns a list of dictionaries. Each dictionary contains the
        following keys, which are also returned by API method get_cookie_attributes: "name", "value", "expires",
        "max-age", "domain", "path", "secure", "httponly", "samesite"
        """
        if isinstance(filter, str):
            filter = [filter]
        cookie_attributes = self.get_cookie_attributes()
        result = []
        if isinstance(item, IRequestInfo):
            tmp = list(self.get_headers(item.getHeaders(),
                                        [re.compile("^cookie$", re.IGNORECASE)]).values())
            cookie_values = []
            for item in tmp:
                if not self._ide_pane.activated:
                    return result
                if item:
                    if isinstance(item, list):
                        cookie_values.extend(item)
                    else:
                        cookie_values.append(item)
            for cookie_value in cookie_values:
                if not self._ide_pane.activated:
                    return result
                cookies = [tmp.strip() for tmp in cookie_value.split(";")]
                for cookie in cookies:
                    cookie_info = self._get_dict(cookie_attributes)
                    cookie_info["name"], cookie_info["value"] = self._split_items(cookie)
                    if filter and cookie_info["name"] in filter or not filter:
                        result.append(cookie_info)
        elif isinstance(item, IResponseInfo):
            tmp = list(self.get_headers(item.getHeaders(),
                                        [re.compile("^set-cookie", re.IGNORECASE)]).values())
            cookie_values = []
            for item in tmp:
                if not self._ide_pane.activated:
                    return result
                if item:
                    if isinstance(item, list):
                        cookie_values.extend(item)
                    else:
                        cookie_values.append(item)
            for cookie_value in cookie_values:
                if not self._ide_pane.activated:
                    return result
                cookie_info = self._get_dict(cookie_attributes)
                attributes = [tmp.strip() for tmp in cookie_value.split(";")]
                cookie_info["name"], cookie_info["value"] = self._split_items(attributes[0])
                if filter and cookie_info["name"] in filter or not filter:
                    for attribute in attributes[1:]:
                        lookup = attribute.lower()
                        if lookup == "secure":
                            cookie_info["secure"] = True
                        elif lookup == "httponly":
                            cookie_info["httponly"] = True
                        else:
                            key, value = self._split_items(attribute)
                            key = key.lower()
                            if key == "max-age":
                                cookie_info[key] = int(value)
                            else:
                                cookie_info[key] = value
                    if cookie_info["secure"] is None:
                        cookie_info["secure"] = False
                    if cookie_info["httponly"] is None:
                        cookie_info["httponly"] = False
                    if cookie_info["max-age"] is None:
                        cookie_info["max-age"] = 0
                    result.append(cookie_info)
        return result

    def get_header(self, headers, header_name):
        """
        This method is a simplified version of API method get_headers. It analyses a given list of headers and returns
        the first occurrence of the header information that matches a given name.

        :param headers (List[str]): The list of headers that shall be searched for the first occurrence of the given
        header. Usually, the list of headers is obtained via the getHeaders method implemented by Burp Suite's
        IRequestInfo or IResponseInfo interfaces.
        :param header_name (str): The name (case insensitive) of the header whose value shall be returned.
        :return (tuple): Returns the value of the first occurrence of the header as a tuple; the first element is
        the header name and the second elements is its content. If the header was not found, then a tuple containing
        (None, None) is returned.
        """
        lower_header_name = header_name.lower()
        result = (None, None)
        for header in headers:
            if not self._ide_pane.activated:
                return result
            tmp = header.split(":")
            name = tmp[0].lower()
            value = ":".join(tmp[1:]).strip()
            if lower_header_name == name:
                return (name, value)
        return result

    def get_headers(self, headers, re_headers):
        """
        This method analyses a given list of headers and returns all occurrences of the header information that
        matches a given list of regular expressions.

        :param headers (List[str]): The list of headers that shall be searched for the first occurrence of the given
        header. Usually, the list of headers is obtained via the getHeaders method implemented by Burp Suite's
        IRequestInfo or IResponseInfo interfaces.
        :param re_headers (List[re.Pattern]): List of regular expressions that specify the patterns for header names
        whose header values shall be returned.
        :return (Dict[str, List[str]]): The keys of the returned dictionary are always the strings of the re_headers
        list ({item.pattern: [] for item in re_headers}) and the corresponding dictionary values contain the
        identified header values.
        """
        result = {item.pattern: [] for item in re_headers}
        for regex in re_headers:
            if not self._ide_pane.activated:
                return result
            for header in headers:
                tmp = header.split(":")
                name = tmp[0]
                value = ":".join(tmp[1:])
                if regex.match(name):
                    result[regex.pattern].append(value)
        return result

    def get_hostname(self, url):
        """
        This method removes the file and query part of the given URL so that only the protocol, hostname, and port parts
        remain.

        :param url (java.lang.URL): The URL from which the file and query part is removed.
        :return (java.lang.URL): The new java.net.URL instance containing the protocol, host, and port information
        """
        result = None
        if url:
            if (url.getProtocol() == "https" and url.getPort() == 443) or \
               (url.getProtocol() == "http" and url.getPort() == 80):
                result = URL(url.getProtocol(), url.getHost(), "")
            else:
                result = URL(url.getProtocol(), url.getHost(), url.getPort(), "")
        return result

    def get_json_attributes(self, body, attributes, must_match=0):
        """Searches the string stored in the body variable for those attribute names, which are specified by the
        attributes list.

        This method converts the given string body into a JSON object (if not already the case) and then searches
        this JSON object recursively for attributes that are specified by the attributes list.
        :param body (str/dict): Contains the JSON object, which is either of type string or dictionary, that shall be
        searched.
        :param attributes (List[str]): List of attribute names those the values should be extracted from the given
        JSON object.
        :param must_match (int=0): Specifies how many attributes in the provided list must be found on the save level
        in the JSON object in order to be added to the return list. If the parameter is not specified or less than or
        equal to 0, then any occurrence is added to the list.
        :return (List[Dict[str, str]]): The keys of each dictionary represent the values specified in the provided
        attributes list and the values represent the corresponding values extracted from the JSON object.
        :raise ValueError: This exception is thrown when the given body cannot be converted into a
        dictionary.
        """
        result = {}
        json_object = body if isinstance(body, dict) else json.JSONDecoder().decode(body)
        if not isinstance(attributes, list):
            attributes = [attributes]
        must_match = must_match if must_match <= len(attributes) else len(attributes)
        for item in attributes:
            if not self._ide_pane.activated:
                return result
            if item not in result:
                result[item] = None
        result = self._parse_json(json_object, result, must_match)
        return result

    def get_json_attribute_by_path(self, body, path, default_value=None):
        """
        This method returns the JSON attribute located at position path in JSON object body.
        :param body (str/dict): Contains the JSON object, which is either of type string or dictionary, that shall be
        searched.
        :param path (str): Path (e.g. data/value/) that specifies the attribute that shall be returned.
        :param default_value (object): The default value that shall be returned if the requested path does not exist.
        :return (dict): The JSON attribute at location path or default_value.
        :raise ValueError: This exception is thrown when the given body cannot be converted into a
        dictionary.
        """
        path = path[1:] if path[0] == '/' else path
        current_position = body if isinstance(body, dict) else json.JSONDecoder().decode(body)
        for value in path.split("/"):
            if not self._ide_pane.activated:
                return current_position
            if isinstance(current_position, dict) and value in current_position:
                current_position = current_position[value]
            else:
                current_position = None
                break
        return current_position if current_position else default_value

    def get_jwt(self, headers, re_header="^Authorization:\s+Bearer\s+(?P<jwt>.+?\..+?\..+?)$"):
        """
        This method searches the given array of headers for the first occurrence that matches the given authorization
        header and extracts as well as decodes and returns the given JSON Web Token (JWT).

        :param headers (List[str]): List of strings that contain the headers to be searched. Usually, the list of
        headers is obtained via the getHeaders method implemented by Burp Suite's IRequestInfo or IResponseInfo
        interfaces.
        :param re_header: The regular expression string (case insensitive) that specifies how the JWT can be extracted.
        Note that the regular expression must contain the named group jwt, which specifies the position of the jwt to
        be extracted.
        :return (List[str]): List with three string elements. The first element contains the header (or None), the
        second element the payload (or None), and the third element the signature (or None) of the JWT.
        """
        result = [None, None, None]
        jwt_re = re.compile(re_header, re.IGNORECASE)
        for header in headers:
            if not self._ide_pane.activated:
                return result
            jwt_match = jwt_re.match(header)
            if jwt_match:
                jwt = jwt_match.group("jwt")
                result = self.decode_jwt(jwt)
                break
        return result

    def get_parameter_name(self, type):
        """
        This method returns the descriptive name of the given parameter type value. This method is usually used to
        convert the value returned by getType method of the IParameter class into a string (e.g., value 0 is GET, value
        1 is POST, etc.).

        :param type (int): The integer value that shall be returned into the string.
        :return (str): The descriptive name that matches the given type parameter value or None.
        """
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

    def get_parameters(self, request_info, re_names):
        """
        This method analyses the parameters of the given IRequestInfo object and returns all occurrences of parameters
        whose names match one of the given regular expressions.

        :param request_info (RequestInfo): The IRequestInfo object whose parameters shall be analysed.
        :param re_names (List[re.Pattern]): List of regular expressions that specify the patterns for parameter names
        whose parameter values shall be returned.
        :return (Dict[str, List[IParameter]]): The keys of the returned dictionary are always the strings of the
        re_names list ({item.pattern: [] for item in re_names}) and the corresponding dictionary values contain the
        IParameter objects whose names matched the corresponding regular expression.
        """
        result = {item.pattern: [] for item in re_names}
        for regex in re_names:
            if not self._ide_pane.activated:
                return result
            pattern = regex.pattern
            for parameter in request_info.getParameters():
                if not self._ide_pane.activated:
                    return result
                name = parameter.getName()
                if regex.match(name):
                    result[pattern].append(parameter.getValue())
        return result

    def has_header(self, headers, name):
        """
        This method checks whether the given header exists in the list of headers. The search is case insensitive.

        :param headers (List[str]): The list of headers that shall be searched to determine if the given header name
        exists.
        :param name (str): The header name that shall be searched.
        :return (bool): True, if the given header name exists in the headers list, else False.
        """
        re_header_name = "^{}:.*$".format(name)
        result = False
        for header in headers:
            if not self._ide_pane.activated:
                return result
            if re.match(re_header_name, header, re.IGNORECASE):
                return True
        return result

    def get_extension_info(self, content):
        """
        This method analyses the file extension of the given string and returns additional information like file
        category about the first extension that matches.

        :param content (str): The string whose file extension should be analyzed.
        :return (dict): Dictionary containing information about the string's file extension or None if no extension
        was identified. The dictionary contains the following keys: extension (str), category (str), description (str)
        """
        for extension in self._extensions["extensions"]:
            if not self._ide_pane.activated:
                break
            if content.endswith(".{}".format(extension["extension"])):
                return extension
        return None

    def send_http_message(self, request, http_service):
        """
        This method sends the given request to the given HTTP service.

        :param request (str): The request that shall be sent.
        :param http_service (IHttpService): The service to which the given request shall be sent.
        :return (IHttpRequestResponse): Object containing the sent and received data.
        """
        request_binary = self._extender.helpers.stringToBytes(request.replace("\n", "\r\n").strip())
        request_info = self._extender.helpers.analyzeRequest(request_binary)
        headers = request_info.getHeaders()
        body_offset = request_info.getBodyOffset()
        body_bytes = request_binary[body_offset:]
        new_request = self._extender.helpers.buildHttpMessage(headers, body_bytes)
        return self._extender.callbacks.makeHttpRequest(http_service, new_request)

    def split_http_header(self, header):
        """
        This method splits the given header stringinto the header name and value. Usually this method is used in
        combination with the getHeaders method of the IRequestInfo or IResponseInfo interface.

        :param request (str): The header whose header name and value should be returned.
        :return (tuple): The first element contains the header name and the second element the header value. If the
        header is invalid (does not contain a colon), then the (None, None) is returned.
        """
        header_parts = header.split(":")
        if len(header_parts) > 1:
            header_name = header_parts[0]
            header_value = ":".join(header_parts[1:])
        else:
            return None, None
        return unicode(header_name, errors="ignore"), unicode(header_value, errors="ignore")


class IdeTextAreaListener(DocumentListener):
    """
    This class keeps track whether the Python code has changed
    """

    def __init__(self):
        self._changed = False

    @property
    def changed(self):
        return self._changed

    @changed.setter
    def changed(self, value):
        self._changed = value

    def removeUpdate(self, event):
        self._changed = True

    def insertUpdate(self, event):
        self._changed = True

    def changedUpdate(self, event):
        self._changed = True


class IdePane(JPanel):
    """
    This class implements the text area used for writing the Python code
    """

    INSTANCES = []

    def __init__(self, intel_base, pre_script_code=None, post_script_code=None):
        self._compiled_code = None
        self._script_info = ScriptInformation(intel_base.plugin_id)
        self._activated = False
        self._intel_base = intel_base
        self._scripts_dir = intel_base.scripts_dir
        self._activated_lock = Lock()
        self._start_analysis_function = None
        self._stop_analysis_function = None
        self._save_script_function = None
        self._new_script_function = None
        self._clear_session_function = None
        self._pre_script_code = pre_script_code
        self._post_script_code = post_script_code
        self._cb_list = DefaultComboBoxModel()
        self._change_listener = IdeTextAreaListener()
        IdePane.INSTANCES.append(self)

        JScrollPane.__init__(self)
        self.setLayout(BorderLayout())

        scroll_pane = JScrollPane()
        self._text_area = JTextArea()
        self._text_area.getDocument().addDocumentListener(self._change_listener)
        self._text_area.setFont(Font('Monospaced', Font.PLAIN, 11))
        self._text_area.setEditable(True)
        self._text_area.setTabSize(1)
        scroll_pane.setViewportView(self._text_area)
        self.add(scroll_pane, BorderLayout.CENTER)

        components_pane = JPanel()
        self._button_pane = JPanel()
        components_pane.setLayout(BorderLayout())
        self._button_pane.setLayout(GridLayout(1, 4))
        self._code_chooser = JComboBox()
        self._code_chooser.setToolTipText("Select a script and press the Load Script button to load it.")
        self._start_stop_button = JToggleButton("Start", self._activated, actionPerformed=self.start_stop_button_pressed)
        self._start_stop_button.setToolTipText("Press this button to compile the code and start or stop the analysis.")
        self._compile_button = JButton("Compile Code", actionPerformed=self.compile_button_pressed)
        self._compile_button.setToolTipText("Press this button to compile the code. Afterwards, any request/response "
                                            "item can be sent to this extension using Burp Suite's context menu item "
                                            "'Process in Turbo Miner'.")
        self._clear_session_button = JButton("Clear Session", actionPerformed=self.clear_session_button_pressed)
        self._clear_session_button.setToolTipText("Press this button to reset the session variable that is used by "
                                                  "the currently loaded script.")
        self._new_button = JButton("New Script", actionPerformed=self.new_button_pressed)
        self._new_button.setToolTipText("Press this button to create a new script.")
        self._load_button = JButton("Load Script", actionPerformed=self.load_button_pressed)
        self._load_button.setToolTipText("Select a script in the drop down menu and press this button to load it.")
        self._save_button = JButton("Save Script", actionPerformed=self.save_button_pressed)
        self._save_button.setToolTipText("Press this button to save the new or update the existing script.")
        self._refresh_button = JButton("Refresh", actionPerformed=self.refresh_button_pressed)
        self._refresh_button.setToolTipText("Press this button to refresh the combobox.")
        self._code_chooser.setMaximumRowCount(21)
        components_pane.add(self._code_chooser, BorderLayout.NORTH)
        components_pane.add(self._button_pane, BorderLayout.SOUTH)
        self._button_pane.add(self._start_stop_button)
        self._button_pane.add(self._compile_button)
        self._button_pane.add(self._clear_session_button)
        self._button_pane.add(self._save_button)
        self._button_pane.add(self._new_button)
        self._button_pane.add(self._load_button)
        self._button_pane.add(self._refresh_button)
        self.add(components_pane, BorderLayout.SOUTH)
        self.refresh()

    def add_component(self, component):
        """This method can be used to add addtional components to the GUI"""
        self._button_pane.add(component)

    @property
    def code_changed(self):
        return self._change_listener.changed

    @code_changed.setter
    def code_changed(self, value):
        self._change_listener.changed = value

    @property
    def script_info(self):
        self._script_info._script = self._text_area.getText()
        return self._script_info

    @script_info.setter
    def script_info(self, value):
        self._script_info = value
        self._text_area.setText(value.script)
        self._cb_list.setSelectedItem(value)

    @property
    def compiled_code(self):
        return self._compiled_code

    @property
    def activated(self):
        with self._activated_lock:
            rvalue = self._activated
        return rvalue

    @activated.setter
    def activated(self, value):
        with self._activated_lock:
            self._activated = value
            self._start_stop_button.setSelected(value)
            self._start_stop_button.setText("Stop" if value else "Start")
            self._text_area.setEditable(not value)
            self._clear_session_button.setEnabled(not value)
            self._compile_button.setEnabled(not value)
            self._load_button.setEnabled(not value)
            self._save_button.setEnabled(not value)
            self._refresh_button.setEnabled(not value)
            self._new_button.setEnabled(not value)
            self._code_chooser.setEnabled(not value)

    def copy_to_clipboard(self, content):
        """This method takes the parameter and copies it into the clipboard."""
        string_selection = StringSelection(unicode(content))
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(string_selection, None)

    @staticmethod
    def open_file_chooser(parent=None, filter=None):
        """
        Shows file chooser dialog and returns the selected file path

        This method uses JFileChooser to ask users for a file.

        :param parent:
        :param filter: filter = new FileNameExtensionFilter("JPG & GIF Images", "jpg", "gif");
        :return:
        """
        file = None
        chooser = JFileChooser()
        if filter:
            chooser.setFileFilter(filter)
        return_value = chooser.showOpenDialog(parent)
        if return_value == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile().getPath()
        return file

    def refresh(self):
        """This method iterates the given script directory and populates the combo box"""
        scripts = []
        selected_item = self._cb_list.getSelectedItem()
        if not os.path.exists(self._scripts_dir):
            os.makedirs(self._scripts_dir)
        for file in os.listdir(self._scripts_dir):
            if file.endswith(".json"):
                with open(os.path.join(self._scripts_dir, file), "r") as f:
                    content = f.read()
                    if content:
                        script_info = ScriptInformation.load_json(content)
                        for plugin in script_info.plugins:
                            if self._intel_base and plugin and self._intel_base.plugin_id == plugin.plugin_id:
                                scripts.append(script_info)
                                break
        scripts.sort(key=lambda x: x.name)
        self._cb_list = DefaultComboBoxModel(scripts)
        self._code_chooser.setModel(self._cb_list)
        self._cb_list.setSelectedItem(selected_item)

    def force_save_script(self, script_info):
        """
        This file writes the script code to the file regardless whether it already exists.
        Use save_script if you want to ask the user whether file should be overwritten or not
        """
        if not os.path.exists(self._scripts_dir):
            os.makedirs(self._scripts_dir)
        path = os.path.join(self._scripts_dir, "{}.json".format(script_info.uuid))
        with open(path, "w") as f:
            json_object = script_info.get_json()
            f.write(json.dumps(json_object, indent=4))
        # Now we refresh all instances
        for instance in IdePane.INSTANCES:
            instance.refresh()
            instance.code_changed = False

    def save_script(self, script_info):
        """This method is invoked to save the given script to a file"""
        if not os.path.exists(self._scripts_dir):
            os.makedirs(self._scripts_dir)
        path = os.path.join(self._scripts_dir, "{}.json".format(script_info.uuid))
        if os.path.exists(path):
            answer = JOptionPane.showConfirmDialog(self._intel_base.extender.parent,
                                                   "File already exists. Do you want to overwrite it?",
                                                   "Overwrite File?",
                                                   JOptionPane.YES_NO_OPTION)
            if answer == JOptionPane.NO_OPTION:
                return
        self.force_save_script(script_info)

    def register_start_analysis_function(self, function):
        """
        This method must be used to register a function that performs the analysis.
        :param function:
        :return:
        """
        self._start_analysis_function = function

    def register_stop_analysis_function(self, function):
        """
        This method must be used to register a function that is called when the analysis is done
        :param function:
        :return:
        """
        self._stop_analysis_function = function

    def register_clear_session_function(self, function):
        """
        This method must be used to register the function that clears the session data
        :param function:
        :return:
        """
        self._clear_session_function = function

    def compile(self):
        """Creates a new compiled version of the script."""
        self._script_info._script = self._text_area.getText()
        pre_code = "{}{}".format(self._pre_script_code, os.linesep) if self._pre_script_code else ""
        post_code = "{}{}".format(os.linesep, self._post_script_code) if self._post_script_code else ""
        self._compiled_code = compile(pre_code + self._script_info.script + post_code, '<string>', 'exec')
        return self._compiled_code

    def compile_button_pressed(self, event):
        """This method is invoked when the compile button is pressed"""
        try:
            if not self.activated:
                self.compile()
        except:
            ErrorDialog.Show(self._intel_base.extender.parent, traceback.format_exc())

    def start_stop_button_pressed(self, event):
        """This method is invoked when the start button is pressed"""
        try:
            self.activated = self._start_stop_button.isSelected()
            if self.activated:
                self.compile()
                if self._start_analysis_function:
                    self._start_analysis_function()
            else:
                if self._stop_analysis_function:
                    self._stop_analysis_function()
        except:
            ErrorDialog.Show(self._intel_base.extender.parent, traceback.format_exc())
            self.activated = False

    def clear_session_button_pressed(self, event):
        """This method is invoked when the clear session button is pressed"""
        self._clear_session_function()

    def refresh_button_pressed(self, event):
        self.refresh()

    def save_current_script(self):
        """
        This method is used by methods new_button_pressed and load_button_pressed to save the current
        script if desired and update all internal structures accordingly.
        """
        result = None
        if self.code_changed:
            result = JOptionPane.showConfirmDialog(self._intel_base.extender.parent,
                                                   "Do you want to save the changes before you continue?",
                                                   "Save Changed Script Code?",
                                                   JOptionPane.YES_NO_CANCEL_OPTION)
            # If yes, then we save the script to the file system
            if result == JOptionPane.YES_OPTION:
                self.force_save_script(self.script_info)
                self.code_changed = False
            elif result == JOptionPane.NO_OPTION:
                self.code_changed = False
        return result

    def new_button_pressed(self, event):
        """This method is invoked when the new script button is pressed"""
        result = self.save_current_script()
        if result == JOptionPane.CANCEL_OPTION:
            code_changed = self.code_changed
            self._cb_list.setSelectedItem(self.script_info)
            self.code_changed = code_changed
        else:
            self.script_info = ScriptInformation(plugins=[IntelBase.get_plugin_by_id(self._intel_base.plugin_id)])
            self._cb_list.setSelectedItem(self.script_info)
            self.code_changed = False

    def save_button_pressed(self, event):
        """This method is invoked when the save script button is pressed"""
        save_dialog = SaveDialog(self._intel_base.extender.parent, self._intel_base.plugin_category_id, self.script_info)
        save_dialog.pack()
        save_dialog.setVisible(True)
        if not save_dialog.canceled:
            self.save_script(self.script_info)
            if self._cb_list.getSelectedItem() == 0:
                self._cb_list.addElement(self.script_info)
            self._cb_list.setSelectedItem(self.script_info)
            self.code_changed = False
        return JOptionPane.NO_OPTION if save_dialog.canceled else JOptionPane.YES_OPTION

    def load_button_pressed(self, event):
        """This method is invoked when the load button is clicked"""
        new_script = self._cb_list.getSelectedItem()
        if new_script and self.script_info.uuid != new_script.uuid:
            result = self.save_current_script()
            if result == JOptionPane.CANCEL_OPTION:
                code_changed = self.code_changed
                self._cb_list.setSelectedItem(self.script_info)
                self.code_changed = code_changed
            else:
                self.refresh()
                self.script_info = self._cb_list.getSelectedItem()
                self.code_changed = False


class IntelBase(JPanel, IExtensionStateListener):
    """
    This class is the base class for all GUI elements to conduct web application penetration tests
    """

    INSTANCE_COUNT = 1
    SCRIPTS_DIR = "scripts"
    PROXY_HISTORY_ANALYZER = 0
    HTTP_LISTENER_ANALYZER = 1
    PROXY_LISTENER_ANALYZER = 2
    HTTP_LISTENER_MODIFIER = 3
    PROXY_LISTENER_MODIFIER = 4
    CUSTOM_MESSAGE_EDITOR = 5
    SITE_MAP_ANALYZER = 6
    PLUGIN_CATEGORY_ANALYZER = 0
    PLUGIN_CATEGORY_MODIFIER = 1
    PLUGIN_CATEGORY_CUSTOM_MESSAGE_EDITOR = 2
    LIST = [PluginInformation(PROXY_HISTORY_ANALYZER, "Proxy History Analyzer", PLUGIN_CATEGORY_ANALYZER),
            PluginInformation(SITE_MAP_ANALYZER, "Site Map Analyzer", PLUGIN_CATEGORY_ANALYZER),
            PluginInformation(HTTP_LISTENER_ANALYZER, "HTTP Listener Analyzer", PLUGIN_CATEGORY_ANALYZER),
            PluginInformation(HTTP_LISTENER_MODIFIER, "HTTP Listener Modifier", PLUGIN_CATEGORY_MODIFIER),
            PluginInformation(PROXY_LISTENER_MODIFIER, "Proxy Listener Modifier", PLUGIN_CATEGORY_MODIFIER),
            PluginInformation(CUSTOM_MESSAGE_EDITOR, "Custom Message Editor", PLUGIN_CATEGORY_CUSTOM_MESSAGE_EDITOR)]

    def __init__(self, extender, id, plugin_id, plugin_category_id, pre_code=None, post_code=None):
        """
        :param extender:
        :param id: Usually the class name. This information is used for storing the current state in Burp Suite in case
        the extension is unloaded.
        :param plugin_id:
        :param script_dir: The files system directory where the scripts are stored
        """
        JPanel.__init__(self)
        self._id = "{}:{:03d}".format(id, IntelTab.INSTANCE_COUNT)
        IntelBase.INSTANCE_COUNT = IntelBase.INSTANCE_COUNT + 1
        self.setLayout(BorderLayout())
        self._extender = extender
        self._callbacks = extender.callbacks
        self._plugin_category_id = plugin_category_id
        self._helpers = self._callbacks.getHelpers()
        self._plugin_id = plugin_id
        self._scripts_dir = os.path.join(extender.home_dir, IntelBase.SCRIPTS_DIR)
        self._ide_pane = IdePane(self, pre_code, post_code)
        self._exported_methods = ExportedMethods(extender, self._ide_pane)
        self._session = {}
        self._ref_lock = Lock()
        self._ref = 1
        self._ide_pane.code_changed = False
        # load configuration
        try:
            json_object = self._callbacks.loadExtensionSetting("{}_code".format(self._id))
            if json_object:
                json_object = base64.b64decode(json_object)
                json_object = json.JSONDecoder().decode(json_object)
                self._ide_pane.script_info = ScriptInformation.load_json(json_object)
                if "code_changed" in json_object:
                    self._ide_pane.code_changed = json_object["code_changed"]
                else:
                    self._ide_pane.code_changed = False
        except:
            traceback.print_exc(file=self._callbacks.getStderr())
            ErrorDialog.Show(self._extender.parent, traceback.format_exc())
            self._ide_pane.script_info = ScriptInformation(plugins=[IntelBase.get_plugin_by_id(self._plugin_id)])
        self._callbacks.registerExtensionStateListener(self)
        self._ide_pane.register_start_analysis_function(self.start_analysis)
        self._ide_pane.register_stop_analysis_function(self.stop_analysis)
        self._ide_pane.register_clear_session_function(self.clear_session)

    @property
    def id(self):
        return self.id

    @property
    def ide_pane(self):
        return self._ide_pane

    @property
    def extender(self):
        return self._extender

    @property
    def callbacks(self):
        return self._callbacks

    @property
    def plugin_category_id(self):
        return self._plugin_category_id

    @property
    def plugin_id(self):
        return self._plugin_id

    @property
    def scripts_dir(self):
        return self._scripts_dir

    @staticmethod
    def get_plugins_by_category(categories=None):
        rvalues = []
        if not isinstance(categories, list):
            categories = [categories]
        if not categories:
            return IntelBase.LIST
        for plugin in IntelBase.LIST:
            if plugin.category in categories:
                rvalues.append(plugin)
        return rvalues

    @staticmethod
    def get_plugin_by_id(plugin_id):
        for plugin in IntelBase.LIST:
            if plugin.plugin_id == plugin_id:
                return plugin
        return None

    def extensionUnloaded(self):
        """This method is called when the extension is unloaded."""
        try:
            self._ide_pane.activated = False
            script_info = self._ide_pane.script_info
            b64_script_info = script_info.get_json()
            b64_script_info["code_changed"] = self._ide_pane.code_changed
            b64_script_info = json.JSONEncoder().encode(b64_script_info)
            b64_script_info = base64.b64encode(b64_script_info)
            self._callbacks.saveExtensionSetting("{}_code".format(self._id), b64_script_info)
        except:
            traceback.print_exc(file=self._callbacks.getStderr())
            ErrorDialog.Show(self._extender.parent, traceback.format_exc())

    def clear_session(self):
        with self._table_model_lock:
            self._session = {}

    def start_analysis(self):
        """This method is invoked when the analysis is started"""
        raise NotImplementedError("This function is not implemented!")

    def stop_analysis(self):
        """This method is invoked when the analysis is stopped"""
        pass

    def process_proxy_history_entry(self, message_info, is_request=False, tool_flag=None, send_date=None, received_date=None,
                                    listener_interface=None, client_ip_address=None, timedout=None,
                                    message_reference=None, proxy_message_info=None, time_delta=None, in_scope=None):
        raise NotImplementedError("Method not implemented yet")


class DynamicMessageViewer(JTabbedPane):
    """
    This class dynamically adds and removes message information in the IdePane
    """

    def __init__(self, extender, message_editor_controller):
        self._message_infos = {}
        self._messge_info_panes = []
        self._extender = extender
        self._message_editor_controller = message_editor_controller

    @property
    def message_infos(self):
        return self._message_infos

    @message_infos.setter
    def message_infos(self, value):
        if isinstance(value, dict):
            # Set new message infos
            self._message_infos = value
            # Remove current tabs and reset message info pane list
            for pane in self._messge_info_panes:
                self.remove(pane)
            self._messge_info_panes = []
            # Add new tabs
            for key, message_info in self._message_infos.items():
                if isinstance(message_info, IHttpRequestResponse) and isinstance(key, str):
                    pane = MessageViewPane(self._extender, self._message_editor_controller)
                    pane.set_message_info(message_info)
                    self._messge_info_panes.append(pane)
                    self.addTab(key, pane)


class IntelTab(IntelBase):
    """
    This abstract class holds all GUI elements like JTable or IDEPanel to implement to implement an analyzer GUI
    """

    def __init__(self, extender, id, plugin_id):
        """
        :param extender:
        :param id: Usually the class name. This information is used for storing the current state in Burp Suite in case
        the extension is unloaded.
        :param plugin_id:
        :param script_dir: The files system directory where the scripts are stored
        """
        IntelBase.__init__(self, extender, id, plugin_id, IntelBase.PLUGIN_CATEGORY_ANALYZER)
        self._table_model_lock = RLock()
        self._data_model = IntelDataModel()
        self._table = IntelTable(self, self._data_model, self._table_model_lock)
        self._message_info_pane = MessageViewPane(extender, self._table)

        split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        split_pane.setOneTouchExpandable(True)
        self.add(split_pane, BorderLayout.CENTER)

        # table of extracted entries
        scroll_pane = JScrollPane()
        scroll_pane.setViewportView(self._table)
        split_pane.setLeftComponent(scroll_pane)

        # tabbed pane containing IDE and table details
        self._work_tabbed_pane = DynamicMessageViewer(extender, self._table)
        split_pane.setRightComponent(self._work_tabbed_pane)

        self._work_tabbed_pane.addTab("Python", self._ide_pane)
        self._work_tabbed_pane.addTab("Message Information", self._message_info_pane)

        split_pane.setDividerLocation(0.5)

    @property
    def message_info_pane(self):
        return self._message_info_pane

    @property
    def work_tab_pane(self):
        return self._work_tabbed_pane

    @property
    def data_model(self):
        return self._data_model

    @property
    def request_details(self):
        return self._request_details

    @property
    def response_details (self):
        return self._response_details

    def process_proxy_history_entry(self, message_info, is_request=False, tool_flag=None, send_date=None, received_date=None,
                                    listener_interface=None, client_ip_address=None, timedout=None,
                                    message_reference=None, proxy_message_info=None, time_delta=None, row_count=None,
                                    in_scope=None):
        """
        This method executes the Python script for each HTTP request response item in the HTTP proxy history.
        :return: Returns True if exection was successful else False
        """
        if not message_info:
            return
        header = []
        rows = []
        message_infos = {}
        # Setup API
        request_info = self._helpers.analyzeRequest(message_info)
        url = request_info.getUrl()
        in_scope = self._callbacks.isInScope(url) if in_scope is None else in_scope

        globals = {
            'callbacks': self._callbacks,
            'xerceslib': self._extender.xerces_classloader,
            'plugin_id': self._plugin_id,
            'row_count': row_count,
            'get_json_attributes': self._exported_methods.get_json_attributes,
            'get_json_attribute_by_path': self._exported_methods.get_json_attribute_by_path,
            'get_headers': self._exported_methods.get_headers,
            'get_parameters': self._exported_methods.get_parameters,
            'get_parameter_name': self._exported_methods.get_parameter_name,
            'get_header': self._exported_methods.get_header,
            'get_cookies': self._exported_methods.get_cookies,
            'get_cookie_attributes': self._exported_methods.get_cookie_attributes,
            'compress_gzip': self._exported_methods.compress_gzip,
            'decompress_gzip': self._exported_methods.decompress_gzip,
            'get_hostname': self._exported_methods.get_hostname,
            'get_content_length': self._exported_methods.get_content_length,
            'get_content_type': self._exported_methods.get_content_type,
            'analyze_signatures': self._exported_methods.analyze_signatures,
            'get_extension_info': self._exported_methods.get_extension_info,
            'find_versions': self._exported_methods.find_versions,
            'find_domains': self._exported_methods.find_domains,
            'decode_html': self._exported_methods.decode_html,
            'analyze_request': self._exported_methods.analyze_request,
            'analyze_response': self._exported_methods.analyze_response,
            'get_jwt': self._exported_methods.get_jwt,
            'decode_jwt': self._exported_methods.decode_jwt,
            'encode_jwt': self._exported_methods.encode_jwt,
            'send_http_message': self._exported_methods.send_http_message,
            'split_http_header': self._exported_methods.split_http_header,
            'has_header': self._exported_methods.has_header,
            'helpers': self._helpers,
            'header': header,
            'rows': rows,
            'url': url,
            'message_info': message_info,
            'message_infos': message_infos,
            'request_info': request_info,
            'session': self._session,
            'in_scope': in_scope,
            'ref': self._ref
        }
        if tool_flag:
            globals["tool_flag"] = tool_flag
        if send_date:
            globals["sent_date"] = send_date
        if received_date:
            globals["received_date"] = received_date
        if listener_interface:
            globals["listener_interface"] = listener_interface
        if client_ip_address:
            globals["client_ip_address"] = client_ip_address
        if timedout is not None:
            globals["timedout"] = timedout
        if message_reference:
            globals["message_reference"] = message_reference
        if time_delta:
            globals["time_delta"] = time_delta
        # Execute compiled code
        exec(self.ide_pane.compiled_code, globals)
        # Reimport writable API variables
        self._session = globals['session']
        rows = globals['rows']
        header = globals['header']
        message_infos = globals['message_infos']
        # Create new table row
        entries = []
        for row in rows:
            if isinstance(row, list):
                entries.append(IntelDataModelEntry(row, message_info, message_infos))
            else:
                entries.append(IntelDataModelEntry([row], message_info, message_infos))
        # Setup table header
        if self._ref <= 1:
            self._data_model.set_header(header, reset_column_count=True)
        elif row_count and self._ref == (row_count - 1) and not self._data_model.get_header() and header:
            self._data_model.set_header(header, reset_column_count=True)
        # Add new row to table
        with self._table_model_lock:
            self._data_model.add_rows(entries)
        self._ref = self._ref + 1


class ModifierTab(IntelBase):
    """
    This class implements the GUI and base class for on the fly modifications.
    """

    def __init__(self, extender, id, plugin_id):
        IntelBase.__init__(self, extender, id, plugin_id, IntelBase.PLUGIN_CATEGORY_MODIFIER)

    def start_analysis(self):
        """This method is invoked when the analysis is started"""
        self._ref = 1

    def process_proxy_history_entry(self, message_info, is_request=False, tool_flag=None, send_date=None, received_date=None,
                                    listener_interface=None, client_ip_address=None, timedout=None,
                                    message_reference=None, proxy_message_info=None, time_delta=None, in_scope=None):
        """
        This method executes the Python script for each HTTP request response item in the HTTP proxy history.
        :return: Returns True if execution was successful else False
        """
        if not message_info:
            return
        header = []
        rows = []
        # Setup API
        request_info = self._helpers.analyzeRequest(message_info)
        url = request_info.getUrl()
        in_scope = self._callbacks.isInScope(url) if in_scope is None else in_scope

        globals = {
            'callbacks': self._callbacks,
            'xerceslib': self._extender.xerces_classloader,
            'plugin_id': self._plugin_id,
            'is_request': is_request,
            'get_json_attributes': self._exported_methods.get_json_attributes,
            'get_json_attribute_by_path': self._exported_methods.get_json_attribute_by_path,
            'get_headers': self._exported_methods.get_headers,
            'get_header': self._exported_methods.get_header,
            'get_cookies': self._exported_methods.get_cookies,
            'get_cookie_attributes': self._exported_methods.get_cookie_attributes,
            'get_parameters': self._exported_methods.get_parameters,
            'get_parameter_name': self._exported_methods.get_parameter_name,
            'compress_gzip': self._exported_methods.compress_gzip,
            'decompress_gzip': self._exported_methods.decompress_gzip,
            'get_content_length': self._exported_methods.get_content_length,
            'get_content_type': self._exported_methods.get_content_type,
            'get_hostname': self._exported_methods.get_hostname,
            'analyze_signatures': self._exported_methods.analyze_signatures,
            'get_extension_info': self._exported_methods.get_extension_info,
            'find_versions': self._exported_methods.find_versions,
            'find_domains': self._exported_methods.find_domains,
            'decode_html': self._exported_methods.decode_html,
            'analyze_request': self._exported_methods.analyze_request,
            'analyze_response': self._exported_methods.analyze_response,
            'get_jwt': self._exported_methods.get_jwt,
            'decode_jwt': self._exported_methods.decode_jwt,
            'encode_jwt': self._exported_methods.encode_jwt,
            'send_http_message': self._exported_methods.send_http_message,
            'split_http_header': self._exported_methods.split_http_header,
            'has_header': self._exported_methods.has_header,
            'helpers': self._helpers,
            'header': header,
            'rows': rows,
            'url': url,
            'message_info': message_info,
            'request_info': request_info,
            'session': self._session,
            'in_scope': in_scope,
            'ref': self._ref
        }
        if tool_flag:
            globals["tool_flag"] = tool_flag
        if listener_interface:
            globals["listener_interface"] = listener_interface
        if client_ip_address:
            globals["client_ip_address"] = client_ip_address
        if message_reference:
            globals["message_reference"] = message_reference
        if proxy_message_info:
            globals["proxy_message_info"] = proxy_message_info
        # Execute script
        exec(self.ide_pane.compiled_code, globals)
        # Reimport API variables
        self._session = globals['session']
        self._ref = self._ref + 1


class CustomMessageEditorTabBase(IntelBase):
    """
    This class implements the GUI and base class for on the fly modifications.
    """

    def __init__(self, extender, id, plugin_id, pre_code=None, post_code=None):
        IntelBase.__init__(self, extender, id, plugin_id, IntelBase.PLUGIN_CATEGORY_CUSTOM_MESSAGE_EDITOR,
                           pre_code, post_code)


class AnalyzerBase(IntelTab):
    """
    This class implements the base functionality for the proxy history and site map analyzer
    """

    def __init__(self, extender, name, type):
        IntelTab.__init__(self, extender, name, type)
        self._process_thread = None
        self._lock = Lock()

    def _start_analysis(self, entries):
        """This method is invoked when the analysis is started"""
        self._ref = 1

        try:
            self._process_thread = threading.Thread(target=self.process_proxy_history_entries, args=(entries, ))
            self._process_thread.daemon = True
            self._process_thread.start()
        except:
            traceback.print_exc(file=self._callbacks.getStderr())
            ErrorDialog.Show(self._extender.parent, traceback.format_exc())
            self._ide_pane.activated = False

    def stop_analysis(self):
        """This method is invoked when the analysis is stopped"""
        self._process_thread.join()

    def process_proxy_history_entries(self, entries):
        """Iterates through all entries of the HTTP proxy history and processes them."""
        try:
            self._data_model.clear_data()
            row_count = len(entries)
            for message_info in entries:
                if not self._ide_pane.activated:
                    break
                self.process_proxy_history_entry(message_info, IBurpExtenderCallbacks.TOOL_PROXY, row_count=row_count)
            self._ide_pane.activated = False
        except:
            traceback.print_exc(file=self._callbacks.getStderr())
            ErrorDialog.Show(self._extender.parent, traceback.format_exc())
            self._ide_pane.activated = False

    def _menu_invocation_pressed(self, invocation):
        """
        This method iterates through all selected message info items that were sent to Turbo Data Miner via
        Turbo Data Miner's context menu.
        """
        try:
            self._ref = 1
            self._ide_pane.compile()
            self._ide_pane.activated = True
            messages = invocation.getSelectedMessages()
            row_count = len(messages)
            for message_info in messages:
                self.process_proxy_history_entry(message_info,
                                                 invocation.getToolFlag(),
                                                 in_scope=True,
                                                 row_count=row_count)
            self._ide_pane.activated = False
        except:
            traceback.print_exc(file=self._callbacks.getStderr())
            ErrorDialog.Show(self._extender.parent, traceback.format_exc())
            self._ide_pane.activated = False

    def menu_invocation_pressed(self, invocation):
        """This method is invoked when Turbo Data Miner's context menu is selected"""
        self._ref = 1

        try:
            self._process_thread = threading.Thread(target=self._menu_invocation_pressed, args=(invocation, ))
            self._process_thread.daemon = True
            self._process_thread.start()
        except:
            traceback.print_exc(file=self._callbacks.getStderr())
            ErrorDialog.Show(self._extender.parent, traceback.format_exc())
            self._ide_pane.activated = False


class ProxyHistoryAnalyzerBase(AnalyzerBase):
    """
    This class implements the proxy history analyzer
    """

    def __init__(self, extender):
        AnalyzerBase.__init__(self, extender, ProxyHistoryAnalyzerBase.__name__, IntelBase.PROXY_HISTORY_ANALYZER)

    def start_analysis(self):
        with self._lock:
            entries = [item for item in self._callbacks.getProxyHistory()]
        self._start_analysis(entries)


class SiteMapAnalyzerBase(AnalyzerBase):
    """
    This class implements the site map analyzer
    """

    def __init__(self, extender):
        AnalyzerBase.__init__(self, extender, SiteMapAnalyzerBase.__name__, IntelBase.SITE_MAP_ANALYZER)

    def start_analysis(self):
        with self._lock:
            entries = [item for item in self._callbacks.getSiteMap(None)]
        self._start_analysis(entries)


class HttpListenerAnalyzer(IntelTab, IHttpListener):
    """
    Analyzes information delivered through the IHttpListener interface
    """

    def __init__(self, extender):
        IntelTab.__init__(self, extender, HttpListenerAnalyzer.__name__, IntelBase.HTTP_LISTENER_ANALYZER)

    def start_analysis(self):
        """This method is invoked when the analysis is started"""
        self._ref = 1

    def processHttpMessage(self, tool_flag, is_request, message_info):
        """
        This method is invoked when an HTTP request is about to be issued, and when an HTTP response has been received.
        :param tool_flag: Burp Suite tool that issued the request
        :param is_request: True or false depending on whether the provided message is a request or response.
        :param message_info: Contains the actual information in form of an IHttpRequestResponse instance.
        :return:
        """
        try:
            if self._ide_pane.activated and not is_request:
                self.process_proxy_history_entry(message_info, is_request, tool_flag)
        except:
            traceback.print_exc(file=self._callbacks.getStderr())
            ErrorDialog.Show(self._extender.parent, traceback.format_exc())
            self._ide_pane.activated = False


class HttpListenerModifier(ModifierTab, IHttpListener):
    """
    Modifies requests and responses on the fly through the IHttpListener interface
    """

    def __init__(self, extender):
        ModifierTab.__init__(self, extender, HttpListenerModifier.__name__, IntelBase.HTTP_LISTENER_MODIFIER)
        self.add(self._ide_pane)

    def processHttpMessage(self, tool_flag, is_request, message_info):
        """
        This method is invoked when an HTTP request is about to be issued, and when an HTTP response has been received.
        :param tool_flag: Burp Suite tool that issued the request
        :param is_request: True or false depending on whether the provided message is a request or response.
        :param message_info: Contains the actual information in form of an IHttpRequestResponse instance.
        :return:
        """
        try:
            if self._ide_pane.activated:
                self.process_proxy_history_entry(message_info, is_request, tool_flag)
        except:
            traceback.print_exc(file=self._callbacks.getStderr())
            ErrorDialog.Show(self._extender.parent, traceback.format_exc())
            self._ide_pane.activated = False


class ProxyListenerModifier(ModifierTab, IProxyListener):
    """
    Modifies requests and responses on the fly through the IProxyListener interface
    """

    def __init__(self, extender):
        ModifierTab.__init__(self, extender, HttpListenerModifier.__name__, IntelBase.PROXY_LISTENER_MODIFIER)
        self.add(self._ide_pane)

    def processProxyMessage(self, is_request, message):
        """
        This method is invoked when an HTTP request is about to be issued, and when an HTTP response has been received.
        :param is_request: True or false depending on whether the provided message is a request or response.
        :param message: Contains the actual information in form of an IHttpRequestResponse instance.
        :return:
        """
        try:
            if self._ide_pane.activated:
                self.process_proxy_history_entry(message.getMessageInfo(),
                                                 is_request,
                                                 proxy_message_info=message)
        except:
            traceback.print_exc(file=self._callbacks.getStderr())
            ErrorDialog.Show(self._extender.parent, traceback.format_exc())
            self._ide_pane.activated = False


class CustomMessageEditorTab(CustomMessageEditorTabBase):
    """
    This class is used by the CustomTextEditorImplementation class. It implements the logic to write, compile, and
    integrate the code into Burp Suite's message editor tab.
    """

    POST_CODE = """_set_message = set_message
_get_message = get_message
_is_enabled = is_enabled"""

    def __init__(self, extender):
        CustomMessageEditorTabBase.__init__(self, extender, CustomMessageEditorTab.__name__,
                                            IntelBase.CUSTOM_MESSAGE_EDITOR, post_code=CustomMessageEditorTab.POST_CODE)
        self._extender = extender
        self._is_enabled = None
        self._set_message = None
        self._get_message = None
        self.add(self._ide_pane)
        self._lock = Lock()

    def start_analysis(self):
        try:
            # Setup API
            self._session = {}

            globals = {
                'callbacks': self._extender.callbacks,
                'xerceslib': self._extender.xerces_classloader,
                'plugin_id': self._plugin_id,
                'get_json_attributes': self._exported_methods.get_json_attributes,
                'get_json_attribute_by_path': self._exported_methods.get_json_attribute_by_path,
                'get_headers': self._exported_methods.get_headers,
                'get_parameters': self._exported_methods.get_parameters,
                'get_parameter_name': self._exported_methods.get_parameter_name,
                'get_header': self._exported_methods.get_header,
                'get_cookies': self._exported_methods.get_cookies,
                'get_cookie_attributes': self._exported_methods.get_cookie_attributes,
                'get_hostname': self._exported_methods.get_hostname,
                'compress_gzip': self._exported_methods.compress_gzip,
                'decompress_gzip': self._exported_methods.decompress_gzip,
                'get_content_length': self._exported_methods.get_content_length,
                'get_content_type': self._exported_methods.get_content_type,
                'analyze_signatures': self._exported_methods.analyze_signatures,
                'get_extension_info': self._exported_methods.get_extension_info,
                'decode_html': self._exported_methods.decode_html,
                'analyze_request': self._exported_methods.analyze_request,
                'analyze_response': self._exported_methods.analyze_response,
                'find_versions': self._exported_methods.find_versions,
                'find_domains': self._exported_methods.find_domains,
                'get_jwt': self._exported_methods.get_jwt,
                'decode_jwt': self._exported_methods.decode_jwt,
                'encode_jwt': self._exported_methods.encode_jwt,
                'send_http_message': self._exported_methods.send_http_message,
                'split_http_header': self._exported_methods.split_http_header,
                'has_header': self._exported_methods.has_header,
                '_set_message': self._set_message,
                '_get_message': self._get_message,
                '_is_enabled': self._is_enabled,
                'helpers': self._helpers
            }
            # Execute script
            exec(self.ide_pane.compiled_code, globals)
            # Reimport API method implementations
            with self._lock:
                self._set_message = globals['_set_message']
                self._get_message = globals['_get_message']
                self._is_enabled = globals['_is_enabled']
        except:
            traceback.print_exc(file=self._callbacks.getStderr())
            ErrorDialog.Show(self._extender.parent, traceback.format_exc())
            self._ide_pane.activated = False

    def stop_analysis(self):
        with self._lock:
            self._set_message = None
            self._get_message = None
            self._is_enabled = None
            self._tab_caption = None

    @property
    def is_enabled(self):
        with self._lock:
            return self._is_enabled

    @property
    def set_message(self):
        with self._lock:
            return self._set_message

    @property
    def get_message(self):
        with self._lock:
            return self._get_message

    @property
    def session(self):
        return self._session

    def process_proxy_history_entry(self, message_info, is_request=False, tool_flag=None, send_date=None,
                                received_date=None, listener_interface=None, client_ip_address=None,
                                timedout=None, message_reference=None, proxy_message_info=None, time_delta=None,
                                in_scope=None):
        pass


class CustomMessageEditorBase(IMessageEditorTab):
    """
    This class implements the base functionalities for the custom editors
    """

    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._editable = editable
        self._custom_editor_tab = extender.custom_editor_tab
        self._current_message = None

    def isEnabled(self, content, is_request):
        rvalue = False
        try:
            if self._custom_editor_tab.is_enabled:
                rvalue = self._custom_editor_tab.is_enabled(content,
                                                            is_request,
                                                            self._custom_editor_tab.session)
        except:
            self._extender.callbacks.printError(traceback.format_exc())
            ErrorDialog.Show(self._extender.parent, traceback.format_exc())
        return rvalue

    def setMessage(self, content, is_request):
        try:
            if self._custom_editor_tab.set_message:
                self._current_message = self._custom_editor_tab.set_message(content,
                                                                            is_request,
                                                                            self._custom_editor_tab.session)
                self._set_message(self._current_message, is_request, self._editable)
            else:
                self._set_message("", is_request, False)
        except:
            self._extender.callbacks.printError(traceback.format_exc())
            ErrorDialog.Show(self._extender.parent, traceback.format_exc())
            # clear our display
            self._set_message("", is_request, False)

    def getMessage(self):
        try:
            if self._custom_editor_tab.get_message:
                text = self._get_message()
                return self._custom_editor_tab.get_message(text, self._custom_editor_tab.session)
            else:
                return None
        except:
            self._extender.callbacks.printError(traceback.format_exc())
            ErrorDialog.Show(self._extender.parent, traceback.format_exc())
            return None

    def getTabCaption(self):
        raise NotImplementedError("Not implemented yet!")

    def getUiComponent(self):
        raise NotImplementedError("Not implemented yet!")

    def _set_message(self, content, is_request, editable):
        raise NotImplementedError("Not implemented yet!")

    def _get_message(self):
        raise NotImplementedError("Not implemented yet!")

    def isModified(self):
        raise NotImplementedError("Not implemented yet!")

    def getSelectedData(self):
        raise NotImplementedError("Not implemented yet!")


class CustomTextEditorImplementation(CustomMessageEditorBase):
    """
    This class implements Burp Suite's interface IMessageEditorTab to add a custom text editor tab in the Burp Suite
    GUI. Internally, this class uses class CustomMessageEditorTab to allow the management of custom editors in the
    Turbo Data Miner extension.
    """
    def __init__(self, extender, controller, editable):
        CustomMessageEditorBase.__init__(self, extender, controller, editable)

        # create an instance of Burp Suite's text editor, to display our deserialized data
        self._text_editor = extender.callbacks.createTextEditor()
        self._text_editor.setEditable(editable)

    def getTabCaption(self):
        return "Turbo Miner"

    def getUiComponent(self):
        return self._text_editor.getComponent()

    def _set_message(self, content, is_request, editable):
        self._text_editor.setText(content)
        self._text_editor.setEditable(editable)

    def _get_message(self):
        return self._text_editor.getText()

    def isModified(self):
        return self._text_editor.isTextModified()

    def getSelectedData(self):
        return self._text_editor.getSelectedText()


class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IMessageEditorTabFactory):
    """
    This class puts it all together by implementing the burp.IBurpExtender interface
    """

    def __init__(self):
        self._callbacks = None
        self._helpers = None
        self._main_tabs = None
        self._pha = None
        self._sma = None
        self._hla = None
        self._pla = None
        self._hlm = None
        self._plm = None
        self._mef = None
        self._custom_editor_tab = None
        self._home_dir = None
        self._parent = None
        self._context_menu_invocation = None
        self._about = None

    def registerExtenderCallbacks(self, callbacks):
        """
        :param callbacks:
        :return:
        """
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        self._home_dir = os.path.dirname(callbacks.getExtensionFilename())
        # Set up About tab
        about_file = os.path.join(self._home_dir, "about.html")
        about_file_content = ""
        if os.path.isfile(about_file):
            with open(about_file, "r") as f:
                about_file_content = f.read()
        self._about = JTextPane()
        self._about.setContentType("text/html")
        self._about.setEditable(False)
        self._about.setText(about_file_content)
        self._about.addHyperlinkListener(self.hyperlink_listener)
        # set our extension name
        callbacks.setExtensionName("Turbo Data Miner")
        self._pha = ProxyHistoryAnalyzerBase(self)
        self._sma = SiteMapAnalyzerBase(self)
        self._hla = HttpListenerAnalyzer(self)
        self._hlm = HttpListenerModifier(self)
        self._plm = ProxyListenerModifier(self)
        self._custom_editor_tab = CustomMessageEditorTab(self)
        self._main_tabs = JTabbedPane()
        analyzer_tabs = JTabbedPane()
        modifier_tabs = JTabbedPane()
        analyzer_tabs.addTab("Proxy History Analyzer", self._pha)
        analyzer_tabs.addTab("Site Map Analyzer", self._sma)
        analyzer_tabs.addTab("HTTP Listener Analyzer", self._hla)
        modifier_tabs.addTab("HTTP Listener Modifier", self._hlm)
        modifier_tabs.addTab("Proxy Listener Modifier", self._plm)
        self._main_tabs.addTab("Analyzers", analyzer_tabs)
        self._main_tabs.addTab("Modifiers", modifier_tabs)
        self._main_tabs.addTab("Custom Message Editor", self._custom_editor_tab)
        self._main_tabs.addTab("About", JScrollPane(self._about))
        # add the custom tab to Burp Suite's UI
        self._callbacks.addSuiteTab(self)
        self._callbacks.customizeUiComponent(self._main_tabs)
        self._callbacks.customizeUiComponent(self._pha)
        self._callbacks.customizeUiComponent(self._hla)
        self._callbacks.customizeUiComponent(self._hlm)
        self._callbacks.customizeUiComponent(self._plm)
        self._callbacks.registerHttpListener(self._hla)
        self._callbacks.registerHttpListener(self._hlm)
        self._callbacks.registerProxyListener(self._plm)
        self._callbacks.registerContextMenuFactory(self)
        self._callbacks.registerMessageEditorTabFactory(self)
        self._parent = SwingUtilities.getRoot(self._main_tabs)
        # Manually load Turbo Data Miner's own Apache Xerces library, which was obtained from:
        # http://xerces.apache.org/mirrors.cgi
        # Note that the files integrity was verified prior its incorporation into Turbo Data Miner.
        # For more information about the issue refer to:
        # https://forum.portswigger.net/thread/saxparser-dependency-delimma-499c057a
        xerces_path = os.path.join(self._home_dir, "data", "xercesImpl.jar")
        self._xerces_classloader = URLClassLoader([URL("file://{}".format(xerces_path))],
                                                  Thread.currentThread().getContextClassLoader())
        sys.path.append(os.path.join(self._home_dir, "data", "libs"))

    def getTabCaption(self):
        return "Turbo Miner"

    def getUiComponent(self):
        return self._main_tabs

    def createMenuItems(self, invocation):
        """
        This method will be called by Burp Suite when the user invokes a context menu anywhere within Burp Suite. The
        factory can then provide any custom context menu items that should be displayed in the context menu, based on
        the details of the menu invocation.

        :param invocation An object that implements the IMessageEditorTabFactory interface, which the extension can
        query to obtain details of the context menu invocation.
        :return: A list of custom menu items (which may include sub-menus, checkbox menu items, etc.) that should be
        displayed. Extensions may return null from this method, to indicate that no menu items are required.
        """
        self._context_menu_invocation = invocation
        menu_items = []
        if invocation.getInvocationContext() in [
            IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
            IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE,
            IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST,
            IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE,
            IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE,
            IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE,
            IContextMenuInvocation.CONTEXT_PROXY_HISTORY,
            IContextMenuInvocation.CONTEXT_INTRUDER_ATTACK_RESULTS]:
            menu_items.append(JMenuItem("Process in Turbo Data Miner (Proxy History Analyzer tab)",
                                        actionPerformed=self.menu_invocation_pressed))
        return menu_items

    def createNewInstance(self, controller, editable):
        return CustomTextEditorImplementation(self, controller, editable)

    def menu_invocation_pressed(self, event):
        """This method will be called when one of the menu items are pressed."""
        self._pha.menu_invocation_pressed(self._context_menu_invocation)

    def hyperlink_listener(self, event):
        """This event handler processes hyperlink click events"""
        if event.getEventType() == HyperlinkEvent.EventType.ACTIVATED:
            description = event.getDescription()
            try:
                # Follow an internal link
                if description and description[0] == "#":
                    self._about.scrollToReference(description[1:])
                # Follow an external link
                elif Desktop.isDesktopSupported():
                    Desktop.getDesktop().browse(event.getURL().toURI())
            except:
                self._callbacks.printError(traceback.format_exc())

    @property
    def callbacks(self):
        return self._callbacks

    @property
    def helpers(self):
        return self._helpers

    @property
    def parent(self):
        return self._parent

    @property
    def home_dir(self):
        return self._home_dir

    @property
    def xerces_classloader(self):
        return self._xerces_classloader

    @property
    def custom_editor_tab(self):
        return self._custom_editor_tab
