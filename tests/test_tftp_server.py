from pathlib import Path
from unittest.mock import patch

import tftp
from tests.tftp_test_case import TFTPTestCase


class TestTFTPServer(TFTPTestCase):
    def setUp(self):
        super(TestTFTPServer, self).setUp()
        self.client_handler_patcher = patch('tftp.TFTPClientHandler')
        self.client_handler = self.client_handler_patcher.start()
        self.server: tftp.TFTPServer = None

    def tearDown(self):
        self.server.__exit__(None, None, None)
        self.client_handler_patcher.stop()
        super(TestTFTPServer, self).tearDown()

    def __create_server(self, root_dir: Path = None,
                        allow_upload: bool = True) -> None:
        if root_dir is None:
            root_dir = self.path_instance
        self.path_instance = root_dir
        self.server = tftp.TFTPServer(
            self.srv_host, self.srv_port, root_dir, allow_upload)
        self.server.__enter__()

    def test_run_server(self):
        self.__create_server()
        self.socket_instance.recvfrom.side_effect = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.server.serve()

    def test_incoming_connection(self):
        self.__create_server()
        self.socket_instance.recvfrom.side_effect = [
            (b'\x00\x01test !@#\x00octet\x00', self.addr),
            KeyboardInterrupt(),
        ]

        with self.assertRaises(KeyboardInterrupt):
            self.server.serve()
        self.client_handler.assert_called_with(
            self.srv_host, self.addr, self.path_instance, True,
            b'\x00\x01test !@#\x00octet\x00')

    def test_incoming_connection_different_settings(self):
        path = self.path()
        addr = ('example.com', 32768)
        self.__create_server(path, False)

        self.socket_instance.recvfrom.side_effect = [
            (b'test', addr),
            KeyboardInterrupt(),
        ]
        with self.assertRaises(KeyboardInterrupt):
            self.server.serve()
        self.client_handler.assert_called_with(
            self.srv_host, addr, path, False, b'test')
