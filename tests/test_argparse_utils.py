import argparse
import unittest
from unittest.mock import patch

from argparse_utils import path_type


class TestPathType(unittest.TestCase):
    def setUp(self):
        self.path_patcher = patch('server.argparse_utils.Path')
        self.path = self.path_patcher.start()
        self.path_str = '/path/to/file'

    def tearDown(self):
        self.path_patcher.stop()

    def test_simple(self):
        path_type()(self.path_str)
        self.path.assert_called_with(self.path_str)

    def test_not_exists(self):
        self.path().exists.return_value = False
        with self.assertRaises(argparse.ArgumentTypeError):
            path_type()(self.path_str)

    def test_not_dir(self):
        self.path().is_dir.return_value = False
        with self.assertRaises(argparse.ArgumentTypeError):
            path_type(check_dir=True)(self.path_str)
