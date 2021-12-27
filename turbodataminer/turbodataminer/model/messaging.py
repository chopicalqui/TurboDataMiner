# -*- coding: utf-8 -*-
"""
This module implements all functionality for async messaging
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

import uuid
import time
import traceback
from threading import Lock
from threading import Thread
from java.util.concurrent import TimeUnit
from java.util.concurrent import LinkedBlockingDeque
from turbodataminer.ui.core.scripting import ErrorDialog


class MessagingQueueItem:
    def __init__(self, request):
        self.request = request
        self.uuid = str(uuid.uuid4())


class CommunicationManager:
    """
    This class implements multi-threaded async sending and receiving of HTTP requests and responses.
    """

    def __init__(self, extender, ide_pane):
        """
        :param extender:
        :param ide_pane:
        """
        self._extender = extender
        self._callbacks = extender.callbacks
        self._http_service_lock = Lock()
        self._http_service = None
        self._ide_pane = ide_pane
        self._queue = LinkedBlockingDeque()
        self._stop_lock = Lock()
        self._callback_method_lock = Lock()
        self._callback_method = None
        self._kwargs = None
        self._cache_lock = Lock()
        self._cache = {}
        self.rows_lock = Lock()
        self.message_infos_lock = Lock()
        self.__stop = False
        self._threads = []

    @property
    def http_service(self):
        with self._http_service_lock:
            result = self._http_service
        return result

    def set_http_service(self, value):
        with self._http_service_lock:
            self._http_service = value

    @property
    def callback_method(self):
        with self._callback_method_lock:
            result = self._callback_method
        return result

    def register_callback(self, method):
        with self._callback_method_lock:
            self._callback_method = method

    def register_arguments(self, **kwargs):
        self._kwargs = kwargs

    @property
    def _stop(self):
        """
        This thread-safe property allows worker threads to determine if the producer thread already signaled that no
        further HTTP requests will be put into the sending queue.
        :return:
        """
        with self._stop_lock:
            result = self.__stop
        return result

    def stop(self):
        """
        This thead-safe method is used by the producer thread to signal worker threads that no further HTTP requests
        are put into the seinding queue.
        :return: The method does not req
        """
        with self._stop_lock:
            self.__stop = True

    def add_http_request(self, request):
        """
        This method is used by the producer thread to add new requests to the sending queue.
        :param request: The request that shall be added to the sending queue.
        :return: GUID
        """
        item = MessagingQueueItem(request)
        result = None
        if self._queue.add(item):
            uuid = item.uuid
            with self._cache_lock:
                self._cache[uuid] = {"uuid": uuid}
                result = self._cache[uuid]
        return result

    def _make_http_request(self):
        """
        This method is used by the worker threads to send HTTP requests.
        :return:
        """
        while not self._stop and self._ide_pane.activated:
            item = self._queue.poll(500, TimeUnit.MILLISECONDS)
            if item:
                try:
                    request_response = self._callbacks.makeHttpRequest(self._http_service, item.request)
                    if self.callback_method:
                        with self._cache_lock:
                            cache = self._cache[item.uuid]
                        self.callback_method(new_message_info=request_response, cache=cache, **self._kwargs)
                except:
                    self._ide_pane.activated = False
                    traceback.print_exc(file=self._callbacks.getStderr())
                    ErrorDialog.Show(self._extender.parent, traceback.format_exc())

    def start(self, thread_count=5):
        """
        This method starts all worker threads
        :param thread_count:
        :return:
        """
        for i in range(0, thread_count):
            thread = Thread(target=self._make_http_request)
            thread.daemon = True
            thread.start()
            self._threads.append(thread)

    def join(self):
        """
        This method waits until the queue is empty and afterwards, notifies all worker threads that work is complete.
        :return:
        """
        # Wait until the queue is empty
        while self._queue.size() != 0 and self._ide_pane.activated:
            time.sleep(.5)
        # Signal threads that no further HTTP requests will be queued.
        self.stop()
        # Wait until all threads are completed.
        for thread in self._threads:
            thread.join()
