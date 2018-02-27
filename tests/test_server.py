import logging
import unittest
from unittest.mock import patch

import server


class TestServer(unittest.TestCase):
    def setUp(self):
        self.tftp_server_patcher = patch('server.TFTPServer')
        self.path_patcher = patch('server.argparse_utils.Path')
        self.basic_config_patcher = patch('server.logging.basicConfig')
        self.tftp_server = self.tftp_server_patcher.start()
        self.path = self.path_patcher.start()
        self.path().exists.return_value = True
        self.basic_config = self.basic_config_patcher.start()

    def tearDown(self):
        self.basic_config_patcher.stop()
        self.path_patcher.stop()
        self.tftp_server_patcher.stop()

    @patch('sys.argv', ['server.py', '/srv/tftp'])
    def test_run_server(self):
        server.main()
        self.basic_config.assert_called_with(level=logging.INFO)
        self.tftp_server.assert_called_with('0.0.0.0', 69, '/srv/tftp', False)
        self.tftp_server().__enter__().serve.assert_called_once()

    @patch('sys.argv',
           ['server.py', '-qu', '-Hexample.com', '-p2048', '/tftp'])
    def test_run_server_options(self):
        server.main()
        self.basic_config.assert_called_with(level=logging.WARNING)
        self.tftp_server.assert_called_with('example.com', 2048, '/tftp', True)
        self.tftp_server().__enter__().serve.assert_called_once()
