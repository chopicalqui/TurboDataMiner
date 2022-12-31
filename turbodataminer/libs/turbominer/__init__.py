"""
TurboDataMiner library allowing users to import and use additional functionalities.
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

# The extension uses the following two variables to register objects IExtensionHelpers and IBurpExtenderCallbacks
# at startup. Afterwards, these objects can be accessed and used by the internal turbominer package.
helpers = None
callbacks = None
montoya_api = None
collaborator_client = None


class UrlBlacklist:
    """
    This class is used by class CookieAuthorizationTestBase to determine whether the authorization test shall be
    applied on a given URL.
    """

    def __init__(self, paths=None, extensions=None):
        self._paths = paths if paths else []
        self._extensions = extensions if extensions else []

    def is_processable(self, message_info):
        """
        Returns true if the given Java URL is not blacklisted via a path or extension.
        :param url: The URL of type java.net.URL that shall be checked.
        :return: True if the given Java URL is not blacklisted, else false.
        """
        url = helpers.analyzeRequest(message_info).getUrl()
        path = url.getPath()
        _, extension = os.path.splitext(path)
        return path not in self._paths and extension not in self._extensions
