import unittest
from unittest.mock import patch, call

import client
from tftp import BLOCK_SIZE


class TestClient(unittest.TestCase):
    def setUp(self):
        self.tftp_client_patcher = patch('client.TFTPClient')
        self.argparse_path_patcher = patch('client.argparse_utils.Path')
        self.path_patcher = patch('client.Path')
        self.tftp_client = self.tftp_client_patcher.start()
        self.argparse_path = self.argparse_path_patcher.start()
        self.argparse_path().exists.return_value = True
        self.path = self.path_patcher.start()
        self.path().exists.return_value = True

    def tearDown(self):
        self.path_patcher.stop()
        self.argparse_path_patcher.stop()
        self.tftp_client_patcher.stop()

    @patch('sys.argv', ['client.py', '-g', 'some/test_file', '127.0.0.1'])
    def test_get(self):
        self.tftp_client().__enter__().get_file.return_value = 'test contents'
        client.main()
        self.tftp_client.assert_called_with('127.0.0.1', 69, BLOCK_SIZE, 1)
        self.path.assert_called_with('test_file')
        self.path().write_bytes.assert_called_once_with('test contents')

    @patch('sys.argv', ['client.py', '-g', 'test_file', '-t', 'dest_file_name',
                        'example.com', '2048'])
    def test_get_with_options(self):
        self.tftp_client().__enter__().get_file.return_value = 'test contents'
        client.main()
        self.tftp_client.assert_called_with('example.com', 2048, BLOCK_SIZE, 1)
        self.path.assert_called_with('dest_file_name')
        self.path().write_bytes.assert_called_once_with('test contents')

    @patch('sys.argv', ['client.py', '-g', 'some/test_file',
                        '--block-size', '8192', '--window-size', '10',
                        '127.0.0.1'])
    def test_get_with_rfc_options(self):
        self.tftp_client().__enter__().get_file.return_value = 'test contents'
        client.main()
        self.tftp_client.assert_called_with('127.0.0.1', 69, 8192, 10)
        self.path.assert_called_with('test_file')
        self.path().write_bytes.assert_called_once_with('test contents')

    @patch('sys.argv', ['client.py', '-p', 'some/test_file', '127.0.0.1'])
    def test_put(self):
        self.path().read_bytes.return_value = 'test contents'
        client.main()
        self.tftp_client.assert_called_with('127.0.0.1', 69, BLOCK_SIZE, 1)
        self.path.assert_has_calls(
            [call('some/test_file'), call('some/test_file')])
        self.tftp_client().__enter__().put_file.assert_called_once_with(
            self.path().name, 'test contents')

    @patch('sys.argv', ['client.py', '-p', 'some/test_file', '-t',
                        'dest_file_name', 'example.com', '2048'])
    def test_put_with_options(self):
        self.path().read_bytes.return_value = 'test contents'
        client.main()
        self.tftp_client.assert_called_with('example.com', 2048, BLOCK_SIZE, 1)
        self.path.assert_called_with('some/test_file')
        self.tftp_client().__enter__().put_file.assert_called_once_with(
            'dest_file_name', 'test contents')

    @patch('sys.argv', ['client.py', '-p', 'some/test_file',
                        '--block-size', '4096', '--window-size', '5',
                        '127.0.0.1'])
    def test_put(self):
        self.path().read_bytes.return_value = 'test contents'
        client.main()
        self.tftp_client.assert_called_with('127.0.0.1', 69, 4096, 5)
        self.path.assert_has_calls(
            [call('some/test_file'), call('some/test_file')])
        self.tftp_client().__enter__().put_file.assert_called_once_with(
            self.path().name, 'test contents')
