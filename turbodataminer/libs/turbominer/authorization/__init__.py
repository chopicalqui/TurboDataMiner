# -*- coding: utf-8 -*-
"""
The objective of this Burp Suite extension is the flexible and dynamic extraction, correlation, and structured
presentation of information from the Burp Suite project as well as the flexible and dynamic on-the-fly modification
of outgoing or incoming HTTP requests using Python scripts. Thus, Turbo Data Miner shall aid in gaining a better and
faster understanding of the data collected by Burp Suite.
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
from burp import IParameter
from turbominer import helpers
from turbominer import callbacks
from turbominer import UrlBlacklist


class SessionBase:
    """
    The base class for user session definitions.
    """

    def __init__(self, name, core):
        """
        Constructor.
        :param core: Core object to access Turbo Data Miner's API functions.
        :param name: The name of the user.
        """
        self.name = name
        self._core = core


class UserSessionBase(SessionBase):
    """
    This class holds all information (e.g., session cookies, CSRF tokens, etc.) for a specific user to check the
    user's effective permissions.
    """

    def __init__(self,
                 cookie_jar=None,
                 parameter_jar=None,
                 header_jar=None,
                 **kwargs):
        """
        Constructor.
        :param cookie_jar: Dictionary containing all relevant cookie values for this user.
        :param parameter_jar: Dictionary containing all relevant parameter values (e.g., CSRF tokens) for this user.
        :param header_jar: Dictionary containing all relevant header values (e.g., CSRF tokens) for this user.
        """
        SessionBase.__init__(self, **kwargs)
        self._cookie_jar = cookie_jar if cookie_jar else {}
        self._parameter_jar = parameter_jar if parameter_jar else {}
        self._header_jar = header_jar if header_jar else {}

    def _update_parameters(self, core, request, request_info):
        """
        This method takes the given request and checks whether one of the GET or POST parameters appear in the
        parameter_jar dictionary or one of the COOKIE parameters appear in the cookie_jar dictionary. If it does, then
        the parameter's value as well as the HTTP request is updated.

        :param core: Core object to access Turbo Data Miner's API functions.
        :param request: Bytes array containing the HTTP request returned by IHttpRequestResponse.getRequest().
        :param request_info: The IRequestInfo object that shall be checked and if necessary updated.
        :return: None or updated HTTP request's byte array.
        """
        result = None
        for parameter in request_info.getParameters():
            parameter_name = parameter.getName()
            if parameter.getType() == IParameter.PARAM_COOKIE and parameter_name in self._cookie_jar:
                new_parameter = helpers.buildParameter(parameter_name,
                                                       self._cookie_jar[parameter_name],
                                                       parameter.getType())
                result = helpers.updateParameter(result,
                                                 new_parameter) if result else helpers.updateParameter(request,
                                                                                                       new_parameter)
            elif parameter.getName() in [IParameter.PARAM_BODY,
                                         IParameter.PARAM_URL] and parameter_name in self._parameter_jar:
                new_parameter = helpers.buildParameter(parameter_name,
                                                       self._parameter_jar[parameter_name],
                                                       parameter.getType())
                result = helpers.updateParameter(result,
                                                 new_parameter) if result else helpers.updateParameter(request,
                                                                                                       new_parameter)
        return result

    def _update_headers(self, core, request, request_info):
        """
        This method takes the given request and checks whether one of the header names appear in the self._header_jar
        dictionary. If it does, then the header's value as well as the HTTP request is updated.

        :param core: Core object to access Turbo Data Miner's API functions.
        :param request: Bytes array containing the HTTP request returned by IHttpRequestResponse.getRequest().
        :param request_info: The IRequestInfo object that shall be checked and if necessary updated.
        :return: Original or updated HTTP request's byte array.
        """
        result = None
        updated = False
        headers = list(request_info.getHeaders())
        for i in range(1, len(headers)):
            header_name, _ = self._core.split_http_header(headers[i])
            if header_name and header_name in self._header_jar:
                updated = True
                headers[i] = unicode(header_name) + u": " + unicode(self._header_jar[header_name])
        if updated:
            body_offset = request_info.getBodyOffset()
            body_content = helpers.bytesToString(request[body_offset:])
            result = helpers.buildHttpMessage(headers, body_content)
        return result if result else request

    def update_request(self, core, request, request_info):
        """
        This method takes the given request and checks whether it should be updated based on the user's jar information.

        :param core: Core object to access Turbo Data Miner's API functions.
        :param request: Bytes array containing the HTTP request returned by IHttpRequestResponse.getRequest().
        :param request_info: The IRequestInfo object that shall be checked and if necessary updated.
        :return: The original or updated HTTP request's byte array.
        """
        result = self._update_parameters(core, request, request_info)
        if result:
            new_request_info = helpers.analyzeRequest(result)
            result = self._update_headers(core, result, new_request_info)
        else:
            result = self._update_headers(core, request, request_info)
        return result if result else request

    def update_cookie_jar(self, core, response_info, body_content):
        """
        Default method that updates the cookie_jar dictionary based on the given IResponseInfo object.

        :param core: Core object to access Turbo Data Miner's API functions.
        :param response_info: The IResponseInfo object based on which the cookie_jar dictionary is updated.
        :param body_content: String object containing the response_info object's body.
        :return: None
        """
        for header in response_info.getHeaders():
            for cookie_name in self._cookie_jar.keys():
                # Extract new cookie value out of Set-Cookie header and update cookie jar
                for m in re.finditer("""^Set-Cookie:\s*(?P<name>.+?)=(?P<value>.+?)$""", header, flags=re.IGNORECASE):
                    name = m.group("name").strip()
                    if cookie_name == name:
                        cookie_value = m.group("value").split(";")[0].strip()
                        self._cookie_jar[cookie_name] = cookie_value

    def update_header_jar(self, core, response_info, body_content):
        """
        Default method that updates the header_jar dictionary based on the given IResponseInfo object.

        :param core: Core object to access Turbo Data Miner's API functions.
        :param response_info: The IResponseInfo object based on which the header_jar dictionary is updated.
        :param body_content: String object containing the response_info object's body.
        :return: None
        """
        for header in response_info.getHeaders():
            header_name, header_value = self._core.split_http_header(header)
            if header_name in self._header_jar:
                self._header_jar[header_name] = header_value

    def update_parameter_jar(self, core, response_info, body_content):
        """
        Default method that updates the parameter_jar dictionary based on the given IResponseInfo object.

        :param core: Core object to access Turbo Data Miner's API functions.
        :param response_info: The IResponseInfo object based on which the parameter_jar dictionary is updated.
        :param body_content: String object containing the response_info object's body.
        :return: None
        """
        pass


class UnauthenticatedSession(SessionBase):
    """
    This class specifies how an unauthorized session should look like and updates IRequestInfo objects
    accordingly.
    """

    def __init__(self, name="Anonymous", remove_headers=None, remove_parameters=None, **kwargs):
        """
        Constructor.
        :param name: The name of the user.
        :param remove_headers: List of authentication/authorization headers that shall be removed form an IRequestInfo
        object in order to make it unauthenticated
        :param remove_parameters: List of authentication/authorization parameters that shall be removed form an
        IRequestInfo object in order to make it unauthenticated
        """
        SessionBase.__init__(self, name=name, **kwargs)
        self._headers = [item.lower() for item in (remove_headers if remove_headers else [])]
        self._parameters = [item.lower() for item in (remove_parameters if remove_parameters else [])]

    def update_request(self, core, request, request_info):
        """
        This method removes all headers and parameters from the given IRequestInfo object in order to make the
        IRequestInfo object an unauthenticated request.

        :param core: Core object to access Turbo Data Miner's API functions.
        :param request: Bytes array containing the HTTP request returned by IHttpRequestResponse.getRequest().
        :param request_info: The IRequestInfo object that shall become unauthenticated.
        :return: The original or updated HTTP request's byte array.
        """
        headers = list(request_info.getHeaders())
        updated = False
        result = request
        # Remove headers used for authorization/authentication.
        i = 1
        while i < len(headers):
            header_name, _ = self._core.split_http_header(headers[i])
            if header_name.lower() in self._headers:
                updated = True
                del(headers[i])
            else:
                i += 1
        # Remove relevant parameters used for some sort of authorization/authentication (e.g., CSRF tokens).
        if self._parameters:
            for parameter in request_info.getParameters():
                if parameter.getName().lower() in self._parameters:
                    result = helpers.removeParameter(result, parameter)
                    updated = True
        if updated:
            result_info = helpers.analyzeRequest(result)
            body_offset = result_info.getBodyOffset()
            body_content = helpers.bytesToString(result[body_offset:])
            result = helpers.buildHttpMessage(headers, body_content)
        return result


class AuthorizationTestBase:
    """
    This method implements all functionality to perform an authorization test.
    """

    def __init__(self, core, users, tool_flags=None, blacklist=None):
        """
        Constructor.
        :param core: Contains the ExportedMethods object of the respective intel tab. This is necessary in order to
        determine the user action "Stop Script".
        :param users: List of SessionBase objects for which authorization tests shall be executed.
        :param tool_flags: List of integers defining the Burp sources of interest for authorization testing
        (default is IBurpExtenderCallbacks.TOOL_PROXY).
        """
        self._core = core
        self._users = users
        self._blacklist = blacklist if blacklist else UrlBlacklist()
        self._tool_flags = tool_flags if tool_flags else [callbacks.TOOL_PROXY, callbacks.TOOL_REPEATER]
        self._ref = 1

    def _send_request(self, message_info, request_info, user):
        """
        This method clones the given IHttpRequestResponse object and modifies it to contain the information of the
        second user. Finally, it sends the newly created request and returns the new IHttpRequestResponse object.

        :param message_info: The IHttpRequestResponse object based on which the authorization test shall be performed.
        :param request_info: The IRequestInfo object that shall become unauthenticated.
        :param user (str): The UserSessionBase object the authenticated user for which the authorization test shall be
        performed.
        :return: The new IHttpRequestResponse object.
        """
        # Update the request's parameters and headers
        new_request = user.update_request(self._core, request=message_info.getRequest(), request_info=request_info)
        # Send new request
        return callbacks.makeHttpRequest(message_info.getHttpService(), new_request, False)

    def analyze_response(self, message_info, response_info=None, response_body=None):
        """
        This method extracts all relevant information from the given IHttpRequestResponse object to display it in the
        UI table.

        :param message_info: The IHttpRequestResponse object from which information for the UI table should be extracted.
        :param response_info: The IHttpRequestResponse object's IResponseInfo object.
        :param response_body: The IHttpRequestResponse object's response body as string.
        :return: List of information that shall be displayed in the UI.
        """
        if not response_info:
            response = message_info.getResponse()
            if response:
                response_info = helpers.analyzeResponse(response)
                body_offset = response_info.getBodyOffset()
                response_body = helpers.bytesToString(response[body_offset:])
        return self._analyze_response(message_info, response_info, response_body)

    def _analyze_response(self, message_info, response_info=None, response_body=None):
        """
        This method extracts all relevant information from the given IHttpRequestResponse object to display it in the
        UI table.

        :param message_info: The IHttpRequestResponse object from which information for the UI table shall be extracted.
        :param response_info: The IHttpRequestResponse object's IResponseInfo object.
        :param response_body: The IHttpRequestResponse object's response body as string.
        :return: List of information that shall be displayed in the UI.
        """
        if response_info:
            _, location = get_header(response_info.getHeaders(), "Location")
            # TODO: Update if we want to extract and display additional/different information.
            result = [message_info.getStatusCode(), len(message_info.getResponse()), location if location else ""]
            title = ""
            for m in re.finditer("<title>(?P<title>.+?)</title>", response_body):
                title += m.group("title")
            result.append(title)
        else:
            # TODO: This list should have the same number of items as the list in the if branch.
            result = ["", "", "", ""]
        return result

    def get_table_header(self, custom_columns):
        """
        This method returns the header of the UI table.
        :param custom_columns: Column names, which are returned by method _analyze_response.
        :return: List of column names.
        """
        result = ["Ref", "Method", "Host", "URL"]
        users = ["Base"]
        users += [item.name for item in self._users]
        for user in users:
            result += ["{} ({})".format(item, user) for item in custom_columns]
        return result

    def run(self, tool_flag, message_info):
        """
        This method performs the authorization test based on the given IHttpRequestResponse object.

        :param tool_flag: Integer defining the Burp source of the request (e.g., IBurpExtenderCallbacks.TOOL_PROXY).
        :param message_info: The IHttpRequestResponse object based on which the authorization test shall be performed.
        :return: Tuple containing the row that shall be added to the UI table as the first element and a dictionary
        of name/IHttpRequestResponse pairs to add to the details pane as the second element.
        """
        result = (None, None)
        if tool_flag != callbacks.TOOL_EXTENDER and \
                tool_flag in self._tool_flags and \
                self._blacklist.is_processable(message_info):
            # Initialize the current UI table row and populate it with the information of the base request.
            request_info = helpers.analyzeRequest(message_info)
            url = request_info.getUrl()
            row = [self._ref, request_info.getMethod(), self._core.get_hostname(url), url.getPath()]
            row += self.analyze_response(message_info)
            # Perform authorization test
            check_results = {}
            for user in self._users:
                if self._core.has_stopped():
                    return
                new_message_info = self._send_request(message_info, request_info, user)
                check_results[user.name] = new_message_info
                new_response = new_message_info.getResponse()
                # Analyze the response
                if new_response:
                    new_response_info = helpers.analyzeResponse(new_response)
                    body_offset = new_response_info.getBodyOffset()
                    body_bytes = new_response[body_offset:]
                    body_content = helpers.bytesToString(body_bytes)
                    if not isinstance(user, UnauthenticatedSession):
                        # Based on the new response, we might have to update the user's jar information
                        user.update_cookie_jar(self._core, new_response_info, body_content)
                        user.update_header_jar(self._core, new_response_info, body_content)
                        user.update_parameter_jar(self._core, new_response_info, body_content)
                    # Extract relevant information out of the response for the UI table
                    row += self._analyze_response(new_message_info, new_response_info, body_content)
                else:
                    row += self._analyze_response(new_message_info)
            result = (row, check_results)
            self._ref += 1
        return result
