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
import re
from java.net import URL
from turbominer import helpers
from turbominer import callbacks
from datetime import datetime
from javax.swing import JOptionPane
from ..ui import ParameterScopeDialog
from ..analysis import Parameter
from ..analysis import HttpRequestResponse


class Payload:
	"""
	Implements the base class for payloads.
	"""

	def __init__(self, payload, url_encode=True):
		"""
		Constructor.
		:param payload: The payload that should be tested.
		:param url_encode: If true, then the given argument is URL encoded.
		"""
		self.payload = unicode(payload)
		self._url_encode = url_encode

	def get_payload_parameter(self, parameter):
		"""
		Creates an IParameter object based on the provided IParameter instance.
		:param parameter: The IParameter instance based on which a weaponized IParameter object is created.
		:return: The weaponized IParameter instance.
		"""
		self.payload = helpers.urlEncode(self.payload) if self._url_encode else self.payload
		return helpers.buildParameter(parameter.getName(),
									  unicode(parameter.getValue()) + self.payload if self._append else self.payload,
									  parameter.getType())


class ReflectedPayload(Payload):
	"""
	Specifies a scan payload.
	"""

	def __init__(self, payload, url_encode=True, expected_value="", comment=None, regex=False, append=False):
		"""
		Constructor.
		:param payload: The payload that should be tested.
		:param url_encode: If true, then the given argument is URL encoded.
		:param expected_value: If specified, then this value is expected in the HTTP response.
		:param comment: Comment to describe the given payload.
		:param regex: True, if the expected_value argument is a regular expression.
		:param append: If true, then the payload is appended to the current payload value. If false, then the
		current payload value is fully replaced by the payload.
		"""
		Payload.__init__(self, payload, url_encode)
		self._regex = regex
		self.comment = comment if comment else ""
		self._append = append
		self._expected_value = unicode(expected_value if regex else expected_value)
		self.reflected_values = []

	def check_response(self, message, parameter):
		"""
		Check if the given parameter is somehow reflected back in the given IHttpRequestResponse object.
		:param message: The IHttpRequestResponse that is checked.
		:param parameter: The Parameter instance that is checked whether it got somehow reflected back.
		:return: True if the response got reflected back.
		"""
		result = False
		if message.has_response() and (self._expected_value or self._append):
			response = helpers.bytesToString(message.response)
			if self._regex:
				pattern = re.escape(
					parameter.value) + self._expected_value if self._append else self._expected_value
				for item in re.finditer(pattern, response):
					result = True
					self.reflected_values += list(item.groupdict().values())
				if not result:
					pattern = helpers.urlDecode(re.escape(
						parameter.value)) + self._expected_value if self._append else self._expected_value
					for item in re.finditer(pattern, response):
						result = True
						self.reflected_values += list(item.groupdict().values())
			else:
				pattern = parameter.value + self._expected_value if self._append else self._expected_value
				index = response.find(pattern)
				if index >= 0:
					result = True
					self.reflected_values.append(response[index:index + len(pattern)])
				else:
					pattern = helpers.urlDecode(parameter.value) + self._expected_value if self._append else self._expected_value
					index = response.find(pattern)
					if index >= 0:
						result = True
						self.reflected_values.append(response[index:index + len(pattern)])
		return result


class ScanParameterBase:
	"""
	This class implements all base functionalities to perform scans on parameters.
	"""

	def __init__(self, core, payloads, max_redirects=0):
		"""
		Constructor.
		:param core: Contains the ExportedMethods object of the respective intel tab. This is necessary in order to
		determine the user action "Stop Script".
		:param payloads: Dictionary of ScanItems that shall be used during the scan.
		:param max_redirects: Number of redirects that shall be followed (0 is equal to disabled).
		"""
		self._core = core
		self._max_redirects = max_redirects
		self._payloads = {}
		for key, payloads in payloads.items():
			self._payloads[key] = []
			for payload in payloads:
				self._payloads[key].append(payload)

	def scan(self, request_info):
		"""
		Perform the actual scan.
		:return:
		"""
		raise NotImplementedError("case not implemented")

	def notify_scan_item_completed(self, category, start_time, end_time, payload, parameter, original_message, new_message, redirect_message):
		"""
		Method is called after each parameter has been scanned.
		:param category: Payload category (=key of the payloads dictionary).
		:param start_time: datetime object containing the time when the scan started.
		:param end_time: datetime object containing the time when the scan ended.
		:param payload: ScanItem object used to perform the scan.
		:param parameter: Parameter object containing the parameter that was scanned using the ScanItem.
		:param original_message: The original HttpRequestResponse object on which the scan is based.
		:param new_message: The HttpRequestResponse object that resulted from the scan.
		:param redirect_message: The final HttpRequestResponse object after specified number of redirects.
		:return: No return value
		"""
		raise NotImplementedError("case not implemented")


class SniperScanParameterBase(ScanParameterBase):
	"""This class implements all functionalities to perform a sniper scan on parameters."""

	def __init__(self, **kwargs):
		"""
		Constructor.
		"""
		ScanParameterBase.__init__(self, **kwargs)

	def scan(self, message_info):
		"""
		Performs a scan on the given IRequestInfo object.
		:param message_info: The original IHttpRequestResponse object based on which the scan should be performed.
		:return:
		"""
		scan_scope = ParameterScopeDialog(owner=self._core.parent_ui)
		request = message_info.getRequest()
		service_info = message_info.getHttpService()
		request_info = helpers.analyzeRequest(request)
		if len(request_info.getParameters()) > 0:
			if not scan_scope.display(request_info=request_info):
				return
			for parameter in request_info.getParameters():
				for key, payloads in self._payloads.items():
					for payload in payloads:
						if self._core.has_stopped():
							return
						if scan_scope.match(parameter):
							# Build updated request
							new_parameter = payload.get_payload_parameter(parameter)
							new_request = helpers.updateParameter(request, new_parameter)
							# Send the updated HTTP request
							start = datetime.now()
							new_message_info = callbacks.makeHttpRequest(service_info, new_request, False)
							end = datetime.now()
							redirect_message_info = self._core.follow_redirects(new_message_info,
																				max_redirects=self._max_redirects)
							self.notify_scan_item_completed(category=key,
															start_time=start,
															end_time=end,
															payload=payload,
															parameter=Parameter(parameter),
															original_message=HttpRequestResponse(message_info),
															new_message=HttpRequestResponse(new_message_info),
															redirect_message=HttpRequestResponse(redirect_message_info))
		else:
			JOptionPane.showConfirmDialog(self._core.parent_ui,
				      					  "Request does not contain any parameters and as a result, processing is stopped.",
										  "Processing stopped ...",
										  JOptionPane.DEFAULT_OPTION)
