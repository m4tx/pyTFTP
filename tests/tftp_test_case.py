import unittest

from unittest.mock import patch, MagicMock


class TFTPTestCase(unittest.TestCase):
    def setUp(self):
        self.socket_patcher = patch('tftp.socket')
        self.path_patcher = patch('tftp.Path')

        self.socket = self.socket_patcher.start()
        self.socket_instance: MagicMock = self.socket.socket.return_value
        self.path = self.path_patcher.start()
        self.path_instance = self.path()

        self.instance = None

        self.srv_host = 'localhost'
        self.srv_port = 69
        self.srv_addr = self.srv_host, self.srv_port
        self.addr = ('127.0.0.1', 8192)

    def tearDown(self):
        self.path_patcher.stop()
        self.socket_patcher.stop()
