import re
from turbominer import helpers
from java.net import URL
from burp import IParameter

__all__ = ["ResponseMissingException", "HttpHeader", "HttpRequestResponse"]


class ResponseMissingException(Exception):
    def __init__(self):
        Exception.__init__(self, "HttpRequestResponse does not has a response.")


class Parameter:
    def __init__(self, parameter):
        if not parameter:
            raise ValueError("Argument message_info is empty.")
        self.type = parameter.getType()
        self.name = parameter.getName()
        self.value = parameter.getValue()

    @property
    def type_str(self):
        return Parameter.get_parameter_name(self.type)

    def get_parameter(self):
        return helpers.buildParameter(self.name, self.value, self.type)

    @staticmethod
    def get_parameter_name(type):
        if type == IParameter.PARAM_URL:
            result = "GET"
        elif type == IParameter.PARAM_BODY:
            result = "POST"
        elif type == IParameter.PARAM_COOKIE:
            result = "Cookie"
        elif type == IParameter.PARAM_XML:
            result = "XML"
        elif type == IParameter.PARAM_XML_ATTR:
            result = "XML Attr"
        elif type == IParameter.PARAM_MULTIPART_ATTR:
            result = "Multipart Attr"
        elif type == IParameter.PARAM_JSON:
            result = "JSON"
        else:
            raise NotImplementedError()
        return result

    @staticmethod
    def get_parameter_type(type_name):
        """
        This method returns the parameter type value based on the given descriptive parameter name of the given.
        This method is usually used to convert the value returned by get_parameter_name back to the IParameter type
        value (e.g., "GET" is IParameter.PARAM_URL, "POST" is IParameter.PARAM_BODY, etc.).

        :param type_name (str): The descriptive parameter name that shall be returned as integer.
        :return (str): The integer value that matches the given descriptive parameter name or None.
        """
        if type_name == "GET":
            result = IParameter.PARAM_URL
        elif type_name == "POST":
            result = IParameter.PARAM_BODY
        elif type_name == "Cookie":
            result = IParameter.PARAM_COOKIE
        elif type_name == "XML":
            result = IParameter.PARAM_XML
        elif type_name == "XML Attr":
            result = IParameter.PARAM_XML_ATTR
        elif type_name == "Multipart Attr":
            result = IParameter.PARAM_MULTIPART_ATTR
        elif type_name == "JSON":
            result = IParameter.PARAM_JSON
        else:
            raise NotImplementedError()
        return result


class HttpHeader:
    def __init__(self, header):
        if not header:
            raise ValueError("Argument message_info is empty.")
        self.name = None
        self.value = None
        self.name, self.value = HttpHeader.get_header_from_string(header)

    def get_header(self):
        return self.name + ": " + self.value

    @staticmethod
    def get_header_from_string(header):
        header_parts = header.split(":")
        if len(header_parts) > 1:
            header_name = header_parts[0]
            header_value = ":".join(header_parts[1:])
        else:
            return None, None
        return unicode(header_name, errors="ignore"), unicode(header_value, errors="ignore").strip()


class HttpRequestResponse:
    """
    This class provides an interface to query information from an IHttpRequestResponse instance.
    """

    def __init__(self, message_info):
        if not message_info:
            raise ValueError("Argument message_info is empty.")
        self.message_info = message_info
        self.request = message_info.getRequest()
        self.response = message_info.getResponse()
        self.request_info = None
        self.request_body = None
        self.response_info = None
        self.response_body = None

    @property
    def http_method(self):
        if not self.request_info:
            self.analyze_request()
        return self.request_info.getMethod()

    @property
    def url(self):
        if not self.request_info:
            self.analyze_request()
        return self.request_info.getUrl()

    @property
    def request_content_length(self):
        if not self.request_info:
            self.analyze_request()
        return len(self.request_body)

    @property
    def host_name(self):
        result = None
        url = self.url
        if url:
            if (url.getProtocol() == "https" and url.getPort() == 443) or \
               (url.getProtocol() == "http" and url.getPort() == 80):
                result = URL(url.getProtocol(), url.getHost(), "")
            else:
                result = URL(url.getProtocol(), url.getHost(), url.getPort(), "")
        return result

    @property
    def status_code(self):
        if not self.response_info:
            self.analyze_response()
        return self.response_info.getStatusCode()

    @property
    def get_stated_mime_type(self):
        if not self.response_info:
            self.analyze_response()
        return self.response_info.getStatedMimeType()

    @property
    def get_inferred_mime_type(self):
        if not self.response_info:
            self.analyze_response()
        return self.response_info.getInferredMimeType()

    @property
    def response_content_length(self):
        if not self.response_info:
            self.analyze_response()
        return len(self.response_body)

    @property
    def http_service(self):
        return message_info.getHttpService()

    @property
    def title(self):
        if not self.response_info:
            self.analyze_response()
        result = [item.group("title") for item in re.finditer("<title>(?P<title>.+?)</title>",
                                                              self.response_body,
                                                              flags=re.IGNORECASE)]
        return result[0] if result else None

    def has_response(self):
        return self.response is not None

    def get_parameter(self, name):
        parameter = helpers.getRequestParameter(self.request, name)
        if not parameter:
            raise KeyError("Parameter '{}' not found.".format(name))
        return parameter

    def get_request_header(self, name):
        if not self.request_info:
            self.analyze_request()

    def analyze_response(self):
        if not self.response:
            raise ResponseMissingException()
        self.response_info = helpers.analyzeResponse(self.response)
        self.response_body = self.response[self.response_info.getBodyOffset():]

    def analyze_request(self):
        self.request_info = helpers.analyzeRequest(self.message_info)
        self.body_bytes = self.request[self.request_info.getBodyOffset():]
