# -*- coding: utf-8 -*-
"""
This module implements the UI component for Turbo Data Miner script development.
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

import os
import json
import traceback
from threading import Lock
from javax.swing import JList
from javax.swing import JLabel
from javax.swing import JPanel
from javax.swing import JFrame
from javax.swing import JButton
from javax.swing import JDialog
from javax.swing import JComboBox
from javax.swing import JCheckBox
from javax.swing import JTextArea
from javax.swing import JTextField
from javax.swing import JOptionPane
from javax.swing import JScrollPane
from javax.swing import JFileChooser
from javax.swing import JToggleButton
from javax.swing import DefaultComboBoxModel
from java.awt import Font
from java.awt import Toolkit
from java.awt import Dimension
from java.awt import GridLayout
from java.awt import BorderLayout
from java.awt.event import ItemEvent
from java.awt.event import ItemListener
from java.awt.datatransfer import StringSelection
from turbodataminer.model.scripting import ScriptInformation
from turbodataminer.model.scripting import PluginInformation


class ItemChangeListener(ItemListener):
    """
    This class is used by script combobox to automatically load the newly selected script.
    """

    def __init__(self, update_function):
        ItemListener.__init__(self)
        self._update_function = update_function

    def itemStateChanged(self, event):
        if event.getStateChange() == ItemEvent.SELECTED:
            self._update_function(event)


class ErrorDialog(JDialog):
    """
    This frame is shown if the Python script code entered in the IdePane cannot be compiled or raises an
    error/exception
    """
    def __init__(self, owner, exception):
        super(JDialog, self).__init__(owner, "Compile error", size=(800, 400))
        self._exception = exception
        text_area = JTextArea()
        text_area.setFont(Font("Courier", Font.PLAIN, 11))
        text_area.setText(exception)
        text_area.setEditable(False)
        self.add(JScrollPane(text_area))
        self.setLocationRelativeTo(owner)

    @staticmethod
    def Show(owner, message):
        ef = ErrorDialog(owner, message)
        ef.setVisible(True)


class SaveDialog(JDialog):
    """
    This dialog implements all functionality to save a new or update an existing script.
    """

    def __init__(self, owner,  plugin_category, script_info=ScriptInformation(), title="Save Script"):
        super(JDialog, self).__init__(owner, title, size=(800, 400))
        if script_info.uuid:
            self.script_info = script_info
        else:
            self.script_info = ScriptInformation(name=script_info.name,
                                                 author=script_info.author,
                                                 version=script_info.version,
                                                 plugins=script_info.plugins,
                                                 script=script_info.script,
                                                 burp_professional_only=script_info.burp_professional_only)
        self.setLocationRelativeTo(owner)
        self.setLayout(BorderLayout())
        self.setMaximumSize(Dimension(800, 150))
        self.setMinimumSize(Dimension(800, 150))
        self.setModal(True)
        self.result = None
        self.windowClosing = self.cancel_action

        label_panel = JPanel()
        input_panel = JPanel()
        label_panel.setLayout(GridLayout(6, 1))
        input_panel.setLayout(GridLayout(6, 1))
        self.add(label_panel, BorderLayout.WEST)
        self.add(input_panel, BorderLayout.CENTER)

        self._plugins = PluginInformation.get_plugins_by_category(plugin_category)
        self._select_plugins = JList(self._plugins)
        self._select_plugins.setToolTipText("Select the plugins in which this script will show up.")
        indices = []
        for plugin in script_info.plugins:
            self._select_plugins.setSelectedValue(plugin, True)
            index = self._select_plugins.getSelectedIndex()
            indices.append(index)
        self._select_plugins.setSelectedIndices(indices)
        self.add(self._select_plugins, BorderLayout.EAST)

        l_guid = JLabel("GUID (Filename)")
        tf_guid = JTextField()
        tf_guid.setText(self.script_info.uuid)
        tf_guid.setEditable(False)
        tf_guid.setToolTipText("The unique ID and internal file name of this script.")
        label_panel.add(l_guid)
        input_panel.add(tf_guid)

        l_name = JLabel("Name")
        self._tf_name = JTextField()
        self._tf_name.setToolTipText("Insert a short description for the script.")
        self._tf_name.setText(self.script_info.name)
        label_panel.add(l_name)
        input_panel.add(self._tf_name)

        l_author = JLabel("Author")
        self._ta_author = JTextField()
        self._ta_author.setToolTipText("This field usually contains your name.")
        self._ta_author.setText(self.script_info.author)
        label_panel.add(l_author)
        input_panel.add(self._ta_author)

        l_version = JLabel("Version")
        self._ta_version = JTextField()
        self._ta_version.setText(self.script_info.version)
        self._ta_version.setToolTipText("This script's current version.")
        label_panel.add(l_version)
        input_panel.add(self._ta_version)

        l_burp_professional = JLabel("Burp Professional Only")
        self._cb_burp_professional = JCheckBox("", self.script_info.burp_professional_only)
        self._cb_burp_professional.setToolTipText("Check if the script only works in Burp Suite Professional.")
        label_panel.add(l_burp_professional)
        input_panel.add(self._cb_burp_professional)

        button_panel = JPanel()
        button_panel.setLayout(GridLayout(1, 2))
        input_panel.add(button_panel)

        b_save = JButton("Save", actionPerformed=self.save_action)
        b_cancel = JButton("Cancel", actionPerformed=self.cancel_action)
        button_panel.add(b_save)
        button_panel.add(b_cancel)

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
        self.script_info.plugins = [self._plugins[index] for index in selections]
        self.script_info.name = name
        self.script_info.author = author
        self.script_info.version = version
        self.script_info.burp_professional_only = self._cb_burp_professional.isSelected()
        self.result = JOptionPane.YES_OPTION
        self.setVisible(False)

    def cancel_action(self, event):
        """
        This method is invoked when the cancel button is clicked.
        """
        self.result = JOptionPane.CANCEL_OPTION
        self.setVisible(False)


class IdePane(JPanel):
    """
    This class implements the text area used for writing the Python code
    """

    INSTANCES = []

    def __init__(self, intel_base, pre_script_code=None, post_script_code=None, disable_start_stop_button=False,
                 disable_clear_session_button=False):
        self._compiled_code = None
        self._script_info = ScriptInformation(intel_base.plugin_id)
        self._activated = False
        self._intel_base = intel_base
        self._scripts_dir = intel_base.scripts_dir
        self._activated_lock = Lock()
        self._start_analysis_function_lock = Lock()
        self._stop_analysis_function_lock = Lock()
        self._start_analysis_function = None
        self._stop_analysis_function = None
        self._save_script_function = None
        self._new_script_function = None
        self._clear_session_function = None
        self._pre_script_code = pre_script_code
        self._post_script_code = post_script_code
        self._cb_list = DefaultComboBoxModel()
        # This flag is required to remember the state of the self._text_area component.
        self._code_changed_state = False
        IdePane.INSTANCES.append(self)

        JScrollPane.__init__(self)
        self.setLayout(BorderLayout())

        self._text_area = self._intel_base.callbacks.createTextEditor()
        self._text_area.setEditable(True)
        self.add(self._text_area.getComponent(), BorderLayout.CENTER)

        components_pane = JPanel()
        self._button_pane = JPanel()
        components_pane.setLayout(BorderLayout())
        self._button_pane.setLayout(GridLayout(1, 4))
        self._code_chooser = JComboBox()
        self._code_chooser.setToolTipText("Select a script and press the Load Script button to load it.")
        self._code_chooser.addItemListener(ItemChangeListener(self.load_button_pressed))
        self._start_stop_button = JToggleButton("Start", self._activated, actionPerformed=self.start_stop_button_pressed)
        self._start_stop_button.setEnabled(not disable_start_stop_button)
        self._start_stop_button.setToolTipText("Press this button to compile the code and start or stop the analysis.")
        self._clear_session_button = JButton("Clear Session", actionPerformed=self.clear_session_button_pressed)
        self._clear_session_button.setEnabled(not disable_clear_session_button)
        self._clear_session_button.setToolTipText("Press this button to reset the session variable that is used by "
                                                  "the currently loaded script.")
        self._new_button = JButton("New Script", actionPerformed=self.new_button_pressed)
        self._new_button.setToolTipText("Press this button to create a new script.")
        self._save_button = JButton("Save Script", actionPerformed=self.save_button_pressed)
        self._save_button.setToolTipText("Press this button to save the new or update the existing script.")
        self._refresh_button = JButton("Refresh", actionPerformed=self.refresh_button_pressed)
        self._refresh_button.setToolTipText("Press this button to refresh the combobox.")
        self._delete_button = JButton("Delete Script", actionPerformed=self.delete_button_pressed)
        self._delete_button.setToolTipText("Press this button to delete the currently loaded script.")
        self._code_chooser.setMaximumRowCount(21)
        components_pane.add(self._code_chooser, BorderLayout.NORTH)
        components_pane.add(self._button_pane, BorderLayout.SOUTH)
        self._button_pane.add(self._start_stop_button)
        self._button_pane.add(self._clear_session_button)
        self._button_pane.add(self._save_button)
        self._button_pane.add(self._new_button)
        self._button_pane.add(self._refresh_button)
        self._button_pane.add(self._delete_button)
        self.add(components_pane, BorderLayout.SOUTH)
        self.refresh()

    def add_component(self, component):
        """This method can be used to add addtional components to the GUI"""
        self._button_pane.add(component)

    @property
    def code_changed(self):
        return self._text_area.isTextModified() or self._code_changed_state

    @code_changed.setter
    def code_changed(self, value):
        self._code_changed_state = value
        if not self._code_changed_state:
            tmp = self._text_area.getText()
            self._text_area.setText(tmp)

    @property
    def script_info(self):
        self._script_info._script = self.getScriptText()
        return self._script_info

    @script_info.setter
    def script_info(self, value):
        self._script_info = value
        self._text_area.setText(value.script)
        self._code_changed_state = False
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
            self._refresh_button.setEnabled(not value)
            self._new_button.setEnabled(not value)
            self._code_chooser.setEnabled(not value)
            self._delete_button.setEnabled(not value)

    @staticmethod
    def copy_to_clipboard(content):
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

    def getScriptText(self):
        """
        Returns the script code as string
        :return:
        """
        return self._intel_base.callbacks.getHelpers().bytesToString(self._text_area.getText())

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
                        if self._intel_base.extender.is_burp_professional or (
                            not self._intel_base.extender.is_burp_professional and not script_info.burp_professional_only
                        ):
                            for plugin in script_info.plugins:
                                if self._intel_base and plugin and self._intel_base.plugin_id == plugin.plugin_id:
                                    scripts.append(script_info)
                                    break
                        else:
                            print("The following script requires Burp Suite "
                                  "Professional and therefore was not loaded: {}".format(script_info))
        scripts.sort(key=lambda x: x.name)
        self._cb_list = DefaultComboBoxModel(scripts)
        self._code_chooser.setModel(self._cb_list)
        self._cb_list.setSelectedItem(selected_item)

    def _force_save_script(self, script_info):
        """
        This file writes the script code to the file regardless whether it already exists.
        Use save_script if you want to ask the user whether file should be overwritten or not
        """
        if not os.path.exists(self._scripts_dir):
            os.makedirs(self._scripts_dir)
        path = os.path.join(self._scripts_dir, script_info.file_name)
        with open(path, "w") as f:
            json_object = script_info.get_json()
            f.write(json.dumps(json_object, indent=4))
        # Now we refresh all instances
        for instance in IdePane.INSTANCES:
            instance.refresh()

    def save_current_script(self):
        """
        This method checks checks the status of the current script and if necessary saves it.
        :return: Returns JOptionPane.YES_OPTION, JOptionPane.NO_OPTION or JOptionPane.CANCEL_OPTION. If
        JOptionPane.CANCEL_OPTION is returned, then the caller might also have to cancel the current operation
        (e.g., closing the tab, creating a new script, loading a new script, etc.).
        """
        result = JOptionPane.YES_OPTION
        # We only need to save the script if something changed.
        if self.code_changed:
            # As the user how to proceed.
            result = JOptionPane.showConfirmDialog(self._intel_base.extender.parent,
                                                   "Do you want to save the changes before you continue?",
                                                   "Save Changed Script Code?",
                                                   JOptionPane.YES_NO_CANCEL_OPTION)
            if result == JOptionPane.YES_OPTION:
                if self.script_info.is_new(self._scripts_dir):
                    # The script is new and therefore we need additional information about the script before we can
                    # save it.
                    save_dialog = SaveDialog(self._intel_base.extender.parent,
                                             self._intel_base.plugin_category_id,
                                             self.script_info,
                                             title="Save New Script")
                    save_dialog.pack()
                    save_dialog.setVisible(True)
                    result = save_dialog.result
                    if result == JOptionPane.YES_OPTION:
                        self.script_info = save_dialog.script_info
                        self._force_save_script(self.script_info)
                        if self._cb_list.getSelectedItem() == 0:
                            self._cb_list.addElement(self.script_info)
                        self.code_changed = False
                else:
                    # In this case, the script exists already on the file system and therefore, we ask the user
                    # whether overwriting it is okay.
                    result = JOptionPane.showConfirmDialog(self._intel_base.extender.parent,
                                                           "The script already exists. Do you want to overwrite it?",
                                                           "Overwrite Script File?",
                                                           JOptionPane.YES_NO_CANCEL_OPTION)
                    if result == JOptionPane.YES_OPTION:
                        # In this case, the script exists already on the file system and therefore, we overwrite it.
                        self._force_save_script(self.script_info)
                        self.code_changed = False
            elif result == JOptionPane.NO_OPTION:
                self.code_changed = False
        return result

    def start_stop_script(self):
        """
        This method starts or stops the script depending on the status of the button self._start_stop_button.
        """
        try:
            self.activated = self._start_stop_button.isSelected()
            if self.activated:
                self.compile()
                self.start_analysis_function()
            else:
                self.stop_analysis_function()
        except:
            ErrorDialog.Show(self._intel_base.extender.parent, traceback.format_exc())
            self.activated = False

    def start_analysis_function(self):
        """
        This method is called to start the respective analysis.
        :return:
        """
        with self._start_analysis_function_lock:
            if self._start_analysis_function:
                self._start_analysis_function()

    def stop_analysis_function(self):
        """
        This method is used after stopping/finishing the respective analysis. Thereby, it functions as a cleanup
        function.
        :return:
        """
        with self._stop_analysis_function_lock:
            if self._stop_analysis_function:
                self._stop_analysis_function()

    def register_start_analysis_function(self, function):
        """
        This method must be used to register a function that performs the analysis.
        :param function:
        :return:
        """
        with self._start_analysis_function_lock:
            self._start_analysis_function = function

    def register_stop_analysis_function(self, function):
        """
        This method must be used to register a function that is called when the analysis is done
        :param function:
        :return:
        """
        with self._stop_analysis_function_lock:
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
        self._script_info._script = self.getScriptText()
        pre_code = "{}{}".format(self._pre_script_code, os.linesep) if self._pre_script_code else ""
        post_code = "{}{}".format(os.linesep, self._post_script_code) if self._post_script_code else ""
        self._compiled_code = compile(pre_code + self._script_info.script + post_code, '<string>', 'exec')
        return self._compiled_code

    def start_stop_button_pressed(self, event):
        """This method is invoked when the start button is pressed"""
        self.start_stop_script()

    def clear_session_button_pressed(self, event):
        """This method is invoked when the clear session button is pressed"""
        self._clear_session_function()

    def refresh_button_pressed(self, event):
        self.refresh()

    def delete_button_pressed(self, event):
        result = JOptionPane.showConfirmDialog(self._intel_base.extender.parent,
                                               "Do you really want to delete the currently loaded script?",
                                               "Delete Current Script?",
                                               JOptionPane.YES_NO_OPTION)
        # If yes, then we save the script to the file system
        if result == JOptionPane.YES_OPTION:
            full_path = os.path.join(self._scripts_dir, self.script_info.file_name)
            if os.path.isfile(full_path):
                os.unlink(full_path)
                self.script_info = ScriptInformation(plugins=[PluginInformation.get_plugin_by_id(self._intel_base.plugin_id)])
                self._cb_list.setSelectedItem(self.script_info)
                self.code_changed = False
                self.refresh()

    def new_button_pressed(self, event):
        """This method is invoked when the new script button is pressed"""
        result = self.save_current_script()
        if result == JOptionPane.CANCEL_OPTION:
            code_changed = self.code_changed
            self._cb_list.setSelectedItem(self.script_info)
            self.code_changed = code_changed
        else:
            self.script_info = ScriptInformation(plugins=[PluginInformation.get_plugin_by_id(self._intel_base.plugin_id)])
            self._cb_list.setSelectedItem(self.script_info)
            self.code_changed = False

    def save_button_pressed(self, event):
        """This method is invoked when the save script button is pressed"""
        save_dialog = SaveDialog(self._intel_base.extender.parent, self._intel_base.plugin_category_id, self.script_info)
        save_dialog.pack()
        save_dialog.setVisible(True)
        if save_dialog.result == JOptionPane.YES_OPTION:
            self.script_info = save_dialog.script_info
            self._force_save_script(self.script_info)
            if self._cb_list.getSelectedItem() == 0:
                self._cb_list.addElement(self.script_info)
            self._cb_list.setSelectedItem(self.script_info)
            self.code_changed = False

    def load_button_pressed(self, event):
        """This method is invoked when the load button is clicked"""
        new_script = self._cb_list.getSelectedItem()
        # Only do something, if another script was selected.
        if new_script and self.script_info.uuid != new_script.uuid:
            result = self.save_current_script()
            if result == JOptionPane.CANCEL_OPTION:
                code_changed = self.code_changed
                self._cb_list.setSelectedItem(self.script_info)
                self.code_changed = code_changed
            else:
                self.script_info = self._cb_list.getSelectedItem()
                self.code_changed = False
