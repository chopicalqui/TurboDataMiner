# -*- coding: utf-8 -*-
"""
This module implements the API that can be used by Turbo Data Miner scripts.
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
import json
import traceback
import HTMLParser
from burp import IParameter
from burp import IRequestInfo
from burp import IResponseInfo
from java.net import URL
from java.io import BufferedReader
from java.io import InputStreamReader
from java.io import ByteArrayInputStream
from java.io import ByteArrayOutputStream
from java.lang import String
from javax.swing import JOptionPane
from java.util.zip import GZIPInputStream
from java.util.zip import GZIPOutputStream
from turbodataminer.ui.scoping.scopedialog import ParameterScopeDialog


class IntelFiles:
    """
    This file loads all static data.
    """

    def __init__(self, home_dir):
        self.signatures = {}
        self.extensions = {}
        self.errors = []
        self.vulners_rules = {}
        self.top_level_domains = []
        self.re_domain_name = \
            re.compile("(([\"'/@])|(: )|(\*\.))(?P<domain>(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9])\.?",
                       re.IGNORECASE)
        with open(os.path.join(home_dir, "data/top-level-domains.json"), "r") as f:
            json_object = json.loads(f.read())
            self.top_level_domains = json_object["data"] if "data" in json_object else []
        with open(os.path.join(home_dir, "data/file-signatures.json"), "r") as f:
            self.signatures = json.loads(f.read(), strict=False)
        with open(os.path.join(home_dir, "data/file-extensions.json"), "r") as f:
            self.extensions = json.loads(f.read())
        with open(os.path.join(home_dir, "data/version-vulns.json"), "r") as f:
            self.vulners_rules = json.loads(f.read())
            for name, details in self.vulners_rules["data"]["rules"].items():
                try:
                    tmp = re.compile(details["regex"])
                    details["regex"] = tmp
                except:
                    traceback.print_exc(file=self._extender.callbacks.getStderr())
        with open(os.path.join(home_dir, "data/error-signatures.json"), "r") as f:
            errors = json.loads(f.read())
            for entry in errors["rules"]:
                try:
                    tmp = re.compile(entry["regex"])
                    self.errors.append({"regex": tmp,
                                        "group": entry["group"],
                                        "type": entry["type"],
                                        "severity": entry["severity"],
                                        "confidence": entry["confidence"]})
                    entry["regex"] = tmp
                except:
                    traceback.print_exc(file=self._extender.callbacks.getStderr())


class ExportedMethods:
    """
    This class implements Turbo Data Miner's API
    """

    def __init__(self, extender, ide_pane):
        self._extender = extender
        self._ide_pane = ide_pane
        self._html_parser = HTMLParser.HTMLParser()
        self._signatures = extender.intel_files.signatures
        self._extensions = extender.intel_files.extensions
        self._errors = extender.intel_files.errors
        self._vulners_rules = extender.intel_files.vulners_rules
        self.top_level_domains = extender.intel_files.top_level_domains
        self.re_domain_name = extender.intel_files.re_domain_name

    @property
    def parent_ui(self):
        return self._extender.parent

    def _decode_jwt(self, item):
        result = item.replace('_', '/')
        result = result.replace('-', '+')
        padding = len(unicode(result)) % 4
        if padding == 0:
            pass
        elif padding == 2:
            result += "=="
        elif padding == 3:
            result += "="
        else:
            raise ValueError("illegal base64 string.")
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

    def show_scope_parameter_dialog(self, request_info):
        """
        This method displays a JDialog displaying the given IRequestInfo's parameters. The user can then check
        these parameters as well as specify whether the selection is a black- or whitelisting.
        :param request_info (IRequestInfo): The request object whose parameters is displayed in the JDialog and whose
        parameters can then be filtered using the JDialog object's match method (see below).
        :return: ParameterScopeDialog object that exposes the following methods and variables:
        - canceled: This variable is of type bool and specifies whether the user closed the dialog via the Cancel
        button (canceled == True) or via the Ok button (canceled == False).
        - match(IParameter): This method returns true if the given IParameter parameter was checked by the user in the
        JDialog.
        - whitelisting: This variable specifies whether the user's parameter selection is a white- or blacklisting.

        The following code provides an example of how this method can be used:
        scope_object = show_scope_parameter_dialog(request_info)
        if not scope_object.canceled:
	        for parameter in request_info.getParameters():
                if scope_object.match(parameter):
                    task = "Whitelisting" if scope_object.whitelisting else "Blacklisting"
                else:
                    task = ""
                rows.append([task, get_parameter_name(parameter.getType()), parameter.getName()])
        """
        result = ParameterScopeDialog(owner=self._extender.parent)
        if len(request_info.getParameters()) > 0:
            result.display(request_info=request_info)
        else:
            JOptionPane.showConfirmDialog(self._extender.parent,
                                          "Request does not contain any parameters and as a result, processing is stopped.",
                                          "Processing stopped ...",
                                          JOptionPane.DEFAULT_OPTION)
        return result

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

        :param content (str): The string in which domain names are searched.
        :return (List[str]): List of identified domain names.
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

    def find_error_messages(self, content):
        """
        This method checks whether the given string matches one of the known error signatures based on an internal
        database.

        :param content (str): The string that is tested for known file signatures.
        :return (List[Dict[str, object]]: List of dictionaries. Each dictionary contains the following keys that specify
        information about the matched error signature: regex (str), group (int), type (str), severity(str),
        confidence (str)
        """
        result = []
        for entry in self._errors:
            if not self._ide_pane.activated:
                return result
            if entry["regex"].search(content):
                result.append({"regex": entry["regex"].pattern,
                               "group": entry["group"],
                               "type": entry["type"],
                               "severity": entry["severity"],
                               "confidence": entry["confidence"]})
        return result

    def follow_redirects(self, message_info, max_redirects=1, current_count=0):
        """
        This method analyzes the given IHttpRequestResponse object and if its response performs a redirect, then it
        follows this redirect and returns the resulting IHttpRequestResponse object.

        Note that this method follows redirects recursively until the maximum allowed number of redirects (see parameter
        max_redirects) is reached.

        :param message_info (IHttpRequestResponse): The IHttpRequestResponse object that shall be analyzed to determine
        whether following the redirct is necessary.
        :param max_redirects: Total number of allowed redirects until the redirectin process is
        :param current_count:
        :return:
        """
        # TODO test this function
        result = message_info
        # Check maximum number of redirects
        if current_count < max_redirects:
            response = message_info.getResponse()
            if response:
                # Make sure current response is a redirect
                response_info = self._extender.helpers.analyzeResponse(response)
                if response_info.getStatusCode() == 302:
                    # Analyze request and response
                    http_service = message_info.getHttpService()
                    request_info = self._extender.helpers.analyzeRequest(message_info)
                    # Obtain current URL
                    url = request_info.getUrl()
                    # Obtain redirect location and create new URL
                    _, location = self.get_header(response_info.getHeaders(), "Location")
                    url = URL(url.getProtocol(),
                              url.getHost(),
                              url.getPort(),
                              location) if location.startswith("/") else URL(location)
                    # Redirect to other web application
                    new_request = self._extender.helpers.buildHttpRequest(url)
                    if url.getHost() != http_service.getHost() or \
                            url.getPort() != http_service.getPort() or \
                            url.getProtocol() != http_service.getProtocol():
                        http_service = self._extender.helpers.buildHttpService(url.getHost(),
                                                                               url.getPort(),url.getProtocol())
                    else:
                        # Clone the headers of the original request
                        # We need to convert the strings to java.lang.String else we receive the following exception:
                        #   class org.python.core.PyUnicode cannot be cast to class java.lang.String
                        relevant_headers = [String(self._extender.helpers.analyzeRequest(new_request).getHeaders()[0])]
                        for item in request_info.getHeaders()[1:]:
                            item_lower = item.lower()
                            if not item_lower.startswith("content-length:") and not item_lower.startswith(
                                    "transfer-encoding"):
                                relevant_headers.append(String(item))
                        new_request = self._extender.helpers.buildHttpMessage(relevant_headers, None)
                    new_message_info = self._extender.callbacks.makeHttpRequest(http_service, new_request, False)
                    result = self.follow_redirects(new_message_info,
                                                   current_count=current_count + 1,
                                                   max_redirects=max_redirects)
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
                    result[regex.pattern].append(value.strip())
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

    def get_jwt(self, headers, re_header="^Authorization:\s+Bearer\s+(?P<jwt>eyJ\w+?\.eyJ\w+?\..+?)$"):
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
        return ParameterScopeDialog.get_parameter_name(type)

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

    def has_stopped(self):
        """
        This method returns true, if the user clicked the Stop button to immediately stop the execution of the current
        script. This method should be used within potentially long-lasting loops to check whether the loop should be
        immediately exited.

        :return (bool): True, if the user clicked the Stop, else False.
        """
        return not self._ide_pane.activated

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
        return self._extender.callbacks.makeHttpRequest(http_service, new_request, False)

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
        return unicode(header_name, errors="ignore"), unicode(header_value, errors="ignore").strip()

    def url_decode(self, data, recursive=True):
        """
        This method can be used to URL-decode the specified data. It is an alternative to IExtensionHelpers.urlDecode
        and allows recursively decoding the given value.

        :param data: The data to be decoded.
        :param recursive: If true, then the given data is recusively decoded until it does not change anymore. If
        false, then the value is decoded once.
        :return: The decoded data.
        """
        result = None
        tmp = unicode(data)
        while True:
            result =  self._extender.helpers.urlDecode(tmp)
            if not self._ide_pane.activated:
                result = None
                break
            elif result == tmp or not recursive:
                break
            tmp = result
        return result
