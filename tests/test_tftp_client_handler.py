import errno
from pathlib import Path
from typing import Optional, List, Type
from unittest.mock import patch, call, _Call

import tftp
from tests.tftp_test_case import TFTPTestCase


class TestTFTPClientHandler(TFTPTestCase):
    def setUp(self):
        super(TestTFTPClientHandler, self).setUp()
        self.handler: tftp.TFTPClientHandler = None

    def tearDown(self):
        self.handler.__exit__(None, None, None)
        super(TestTFTPClientHandler, self).tearDown()

    def __create_handler(
            self, root_dir: Path = None, allow_upload: bool = True,
            initial_buffer: bytes = None):
        if root_dir is None:
            root_dir = self.path_instance
        self.path_instance = root_dir
        self.handler = tftp.TFTPClientHandler(
            self.srv_host, self.addr, root_dir, allow_upload, initial_buffer)
        self.handler.__enter__()
        return self.handler

    def test_setup(self):
        self.__create_handler()
        self.socket.socket.assert_called_with(
            self.socket.AF_INET, self.socket.SOCK_DGRAM)
        self.socket_instance.bind.assert_called_with((self.srv_host, 0))

    def __simple_test(
            self, recv_values: List[tftp.Packet], expected_sendto: List[_Call],
            expected_exception: Optional[Type[Exception]] = None,
            read_val: Optional[bytes] = None,
            expected_write: Optional[bytes] = None):
        """Test client handler behavior on given input.

        :param recv_values: list of values that should be returned by recvfrom()
        :param expected_sendto: expected packets sent (as a list of arguments
            for the sendto() function)
        :param expected_exception: expected exception thrown by handle_client()
        :param read_val: contents of the file read
        :param expected_write: expected contents of the file written
        """
        self.__create_handler()
        self.socket_instance.recvfrom.side_effect = recv_values
        self.path_instance.joinpath().read_bytes.return_value = read_val

        if expected_exception is not None:
            with self.assertRaises(expected_exception):
                self.handler.handle_client()
        else:
            self.handler.handle_client()

        if expected_write is not None:
            self.path_instance.joinpath().write_bytes.assert_called_with(
                expected_write)
        self.assertEqual(
            expected_sendto, self.socket_instance.sendto.call_args_list)

    def test_get_empty_file(self):
        recv_vals = [
            (b'\x00\x01test !@#\x00octet\x00', self.addr),
            (b'\x00\x04\x00\x01', self.addr)]
        self.__simple_test(
            recv_vals, [call(b'\x00\x03\x00\x01', self.addr)], read_val=b'')
        self.path_instance.joinpath.assert_called_with('test !@#')

    def test_get_empty_file_initial_buffer(self):
        server = self.__create_handler(
            initial_buffer=b'\x00\x01test !@#\x00octet\x00')
        self.socket_instance.recvfrom.return_value = (
            b'\x00\x04\x00\x01', self.addr)
        self.path_instance.joinpath().read_bytes.return_value = b''
        self.path_instance.joinpath.reset_mock()

        server.handle_client()
        self.path_instance.joinpath.assert_called_once_with('test !@#')
        self.socket_instance.sendto.assert_called_once_with(
            b'\x00\x03\x00\x01', self.addr)

    def test_get_empty_file_additional_fields(self):
        recv_vals = [
            (b'\x00\x01test !@#\x00octet\x00field1\x00field2\x00', self.addr),
            (b'\x00\x04\x00\x01', self.addr)]
        self.__simple_test(
            recv_vals, [call(b'\x00\x03\x00\x01', self.addr)], read_val=b'')
        self.path_instance.joinpath.assert_called_with('test !@#')

    def test_get_short_file(self):
        recv_vals = [
            (b'\x00\x01test !@#\x00octet\x00', self.addr),
            (b'\x00\x04\x00\x01', self.addr)]
        self.__simple_test(
            recv_vals, [call(b'\x00\x03\x00\x01test contents', self.addr)],
            read_val=b'test contents')

    def test_get_long_file(self):
        recv_vals = [
            (b'\x00\x01test !@#\x00octet\x00', self.addr),
            (b'\x00\x04\x00\x01', self.addr),
            (b'\x00\x04\x00\x02', self.addr)]
        expected_sendto = [
            call(b'\x00\x03\x00\x01' + b'a' * 512, self.addr),
            call(b'\x00\x03\x00\x02' + b'a' * 511, self.addr)]
        self.__simple_test(recv_vals, expected_sendto, read_val=b'a' * 1023)

    def test_get_huge_file(self):
        recv_vals = [
            (b'\x00\x01test !@#\x00octet\x00', self.addr)]
        expected_sendto = []
        for i in range(1, 65537):
            block_id = (i % 65536).to_bytes(2, byteorder='big')
            recv_vals.append((b'\x00\x04' + block_id, self.addr))
            expected_sendto.append(
                call(b'\x00\x03' + block_id +
                     b'a' * (0 if i == 65536 else 512), self.addr))

        self.__simple_test(
            recv_vals, expected_sendto, read_val=b'a' * (65535 * 512))

    def test_get_with_blksize_option(self):
        recv_vals = [
            (b'\x00\x01test\x00octet\x00blksize\x008192\x00', self.addr),
            (b'\x00\x04\x00\x00', self.addr),
            (b'\x00\x04\x00\x01', self.addr),
            (b'\x00\x04\x00\x02', self.addr)]
        expected_sendto = [
            call(b'\x00\x06blksize\x008192\x00', self.addr),
            call(b'\x00\x03\x00\x01' + b'a' * 8192, self.addr),
            call(b'\x00\x03\x00\x02' + b'a' * 8191, self.addr)]
        self.__simple_test(recv_vals, expected_sendto, read_val=b'a' * 16383)

    def test_get_with_windowsize(self):
        recv_vals = [
            (b'\x00\x01test\x00octet\x00windowsize\x002\x00', self.addr),
            (b'\x00\x04\x00\x00', self.addr),
            (b'\x00\x04\x00\x02', self.addr),
            (b'\x00\x04\x00\x04', self.addr)]
        expected_sendto = [
            call(b'\x00\x06windowsize\x002\x00', self.addr),
            call(b'\x00\x03\x00\x01' + b'a' * 512, self.addr),
            call(b'\x00\x03\x00\x02' + b'a' * 512, self.addr),
            call(b'\x00\x03\x00\x03' + b'a' * 512, self.addr),
            call(b'\x00\x03\x00\x04' + b'a' * 511, self.addr)]
        self.__simple_test(recv_vals, expected_sendto, read_val=b'a' * 2047)

    @patch('tftp.socket.timeout', Exception)
    def test_get_with_windowsize_timeout(self):
        recv_vals = [
            (b'\x00\x01test\x00octet\x00windowsize\x002\x00', self.addr),
            (b'\x00\x04\x00\x00', self.addr),
            tftp.socket.timeout(),
            (b'\x00\x04\x00\x02', self.addr)]
        expected_sendto = [
            call(b'\x00\x06windowsize\x002\x00', self.addr)] + [
            call(b'\x00\x03\x00\x01' + b'a' * 512, self.addr),
            call(b'\x00\x03\x00\x02' + b'a' * 511, self.addr)] * 2
        self.__simple_test(recv_vals, expected_sendto, read_val=b'a' * 1023)

    def test_get_with_windowsize_half_received(self):
        recv_vals = [
            (b'\x00\x01test\x00octet\x00windowsize\x002\x00', self.addr),
            (b'\x00\x04\x00\x00', self.addr),
            (b'\x00\x04\x00\x01', self.addr),
            (b'\x00\x04\x00\x03', self.addr)]
        expected_sendto = [
            call(b'\x00\x06windowsize\x002\x00', self.addr),
            call(b'\x00\x03\x00\x01' + b'a' * 512, self.addr),
            call(b'\x00\x03\x00\x02' + b'a' * 511, self.addr),
            call(b'\x00\x03\x00\x02' + b'a' * 511, self.addr)]
        self.__simple_test(recv_vals, expected_sendto, read_val=b'a' * 1023)

    def test_get_with_invalid_options(self):
        server = self.__create_handler()
        self.socket_instance.recvfrom.return_value = (
            b'\x00\x01test\x00octet\x00blksize', self.addr)
        with self.assertRaises(tftp.TFTPTerminatedError):
            server.handle_client()
        self.socket_instance.sendto.assert_called_with(
            b'\x00\x05\x00\x08Invalid options specified\x00', self.addr)
        self.socket_instance.close.assert_called()

    def test_get_with_invalid_blksize(self):
        server = self.__create_handler()
        self.socket_instance.recvfrom.return_value = (
            b'\x00\x01test\x00octet\x00blksize\x000\x00', self.addr)
        with self.assertRaises(tftp.TFTPTerminatedError):
            server.handle_client()
        self.socket_instance.sendto.assert_called_with(
            b'\x00\x05\x00\x08Invalid options specified\x00', self.addr)
        self.socket_instance.close.assert_called()

    def test_get_with_invalid_windowsize(self):
        server = self.__create_handler()
        self.socket_instance.recvfrom.return_value = (
            b'\x00\x01test\x00octet\x00windowsize\x0065536\x00', self.addr)
        with self.assertRaises(tftp.TFTPTerminatedError):
            server.handle_client()
        self.socket_instance.sendto.assert_called_with(
            b'\x00\x05\x00\x08Invalid options specified\x00', self.addr)
        self.socket_instance.close.assert_called()

    def test_get_file_absolute_path(self):
        server = self.__create_handler()
        self.socket_instance.recvfrom.side_effect = [
            (b'\x00\x01/etc/fstab\x00octet\x00', self.addr),
            (b'\x00\x04\x00\x01', self.addr),
        ]
        server.handle_client()
        self.path_instance.joinpath.assert_called_with('etc/fstab')

    def test_get_file_parent_directory(self):
        recv_vals = [
            (b'\x00\x01/etc/fstab\x00octet\x00', self.addr),
            (b'\x00\x04\x00\x01', self.addr)]
        expected_sendto = [
            call(b'\x00\x05\x00\x02Access violation\x00', self.addr)]
        self.path_instance.joinpath().relative_to.side_effect = ValueError()
        self.__simple_test(recv_vals, expected_sendto,
                           expected_exception=tftp.TFTPTerminatedError)

    def test_get_file_error_not_found(self):
        self.__test_file_error(OSError(errno.ENOENT, "noent"),
                               b'\x00\x05\x00\x01File not found\x00')

    def test_get_file_error_not_permitted(self):
        self.__test_file_error(OSError(errno.EPERM, "perm"),
                               b'\x00\x05\x00\x02Access violation\x00')

    def test_get_file_error_access_denied(self):
        self.__test_file_error(OSError(errno.EACCES, "perm"),
                               b'\x00\x05\x00\x02Access violation\x00')

    def test_get_file_error_too_big(self):
        self.__test_file_error(
            OSError(errno.EFBIG, "perm"),
            b'\x00\x05\x00\x03Disk full or allocation exceeded\x00')

    def test_get_file_error_no_space(self):
        self.__test_file_error(
            OSError(errno.ENOSPC, "perm"),
            b'\x00\x05\x00\x03Disk full or allocation exceeded\x00')

    def test_get_file_error_unknown(self):
        self.__test_file_error(OSError(errno.EIO, "Error message"),
                               b'\x00\x05\x00\x00Error message\x00')

    def __test_file_error(self, error: OSError, packet: bytes):
        recv_vals = [(b'\x00\x01test !@#\x00octet\x00', self.addr)]
        self.path_instance.joinpath().relative_to.side_effect = error
        self.__simple_test(recv_vals, [call(packet, self.addr)],
                           expected_exception=tftp.TFTPTerminatedError)

    def test_get_invalid_mode(self):
        recv_vals = [(b'\x00\x01test !@#\x00netascii\x00', self.addr)]
        expected_sendto = [
            call(b'\x00\x05\x00\x04Illegal TFTP operation\x00', self.addr)]
        self.__simple_test(recv_vals, expected_sendto,
                           expected_exception=tftp.TFTPTerminatedError)

    def test_get_invalid_format(self):
        recv_vals = [(b'\x00\x01test !@#\x01octet\x01', self.addr)]
        expected_sendto = [
            call(b'\x00\x05\x00\x04Illegal TFTP operation\x00', self.addr)]
        self.__simple_test(recv_vals, expected_sendto,
                           expected_exception=tftp.TFTPTerminatedError)

    def test_put_path_exists(self):
        recv_vals = [(b'\x00\x02test !@#\x00octet\x00', self.addr)]
        expected_sendto = [
            call(b'\x00\x05\x00\x06File already exists\x00', self.addr)]
        self.path_instance.joinpath().exists.return_value = True
        self.__simple_test(recv_vals, expected_sendto,
                           expected_exception=tftp.TFTPTerminatedError)

    def test_put_upload_forbidden(self):
        server = self.__create_handler(allow_upload=False)
        self.socket_instance.recvfrom.return_value = (
            b'\x00\x02test !@#\x00octet\x00', self.addr)
        with self.assertRaises(tftp.TFTPTerminatedError):
            server.handle_client()
        self.socket_instance.sendto.assert_called_once_with(
            b'\x00\x05\x00\x02Access violation\x00', self.addr)

    def test_put_empty_file(self):
        self.path_instance.joinpath().exists.return_value = False
        recv_vals = [
            (b'\x00\x02test !@#\x00octet\x00', self.addr),
            (b'\x00\x03\x00\x01', self.addr)]
        expected_sendto = [
            call(b'\x00\x04\x00\x00', self.addr),
            call(b'\x00\x04\x00\x01', self.addr)]
        self.__simple_test(recv_vals, expected_sendto, expected_write=b'')

    def test_put_short_file(self):
        self.path_instance.joinpath().exists.return_value = False
        recv_vals = [
            (b'\x00\x02test !@#\x00octet\x00', self.addr),
            (b'\x00\x03\x00\x01test contents', self.addr)]
        expected_sendto = [
            call(b'\x00\x04\x00\x00', self.addr),
            call(b'\x00\x04\x00\x01', self.addr)]
        self.__simple_test(
            recv_vals, expected_sendto, expected_write=b'test contents')

    def test_put_long_file(self):
        self.path_instance.joinpath().exists.return_value = False
        recv_vals = [
            (b'\x00\x02test !@#\x00octet\x00', self.addr),
            (b'\x00\x03\x00\x01' + b'a' * 512, self.addr),
            (b'\x00\x03\x00\x02' + b'a' * 511, self.addr)]
        expected_sendto = [
            call(b'\x00\x04\x00\x00', self.addr),
            call(b'\x00\x04\x00\x01', self.addr),
            call(b'\x00\x04\x00\x02', self.addr)]
        self.__simple_test(
            recv_vals, expected_sendto, expected_write=b'a' * 1023)

    def test_put_long_file_with_blksize_option(self):
        self.path_instance.joinpath().exists.return_value = False
        recv_vals = [
            (b'\x00\x02test\x00octet\x00blksize\x008192\x00', self.addr),
            (b'\x00\x03\x00\x01' + b'a' * 8192, self.addr),
            (b'\x00\x03\x00\x02' + b'a' * 8191, self.addr)]
        expected_sendto = [
            call(b'\x00\x06blksize\x008192\x00', self.addr),
            call(b'\x00\x04\x00\x00', self.addr),
            call(b'\x00\x04\x00\x01', self.addr),
            call(b'\x00\x04\x00\x02', self.addr)]
        self.__simple_test(
            recv_vals, expected_sendto, expected_write=b'a' * 16383)

    def test_tftp_error(self):
        server = self.__create_handler()
        self.socket_instance.recvfrom.return_value = (
            b'\x00\x05\x00\x01File not found\x00', self.addr)
        with self.assertRaises(tftp.TFTPError) as cm:
            server.handle_client()

        self.assertEqual(1, cm.exception.error_id)
        self.assertEqual('File not found', cm.exception.message)

    def test_invalid_opcode(self):
        server = self.__create_handler()
        self.socket_instance.recvfrom.return_value = (
            b'\x00\xfftest !@#\x00octet\x00', self.addr)
        with self.assertRaises(tftp.TFTPTerminatedError):
            server.handle_client()
        self.socket_instance.sendto.assert_called_with(
            b'\x00\x05\x00\x04Illegal TFTP operation\x00', self.addr)
        self.socket_instance.close.assert_called()

    def test_invalid_tid(self):
        evil_addr = ('evil.addr.com', 666)
        recv_vals = [
            (b'\x00\x01test !@#\x00octet\x00', self.addr),
            (b'\x00\x04\x00\x01', evil_addr),
            (b'\x00\x04\x00\x01', self.addr)]
        expected_sendto = [
            call(b'\x00\x03\x00\x01test contents', self.addr),
            call(b'\x00\x05\x00\x05Unknown transfer ID\x00', evil_addr)]
        self.__simple_test(
            recv_vals, expected_sendto, read_val=b'test contents')

    @patch('tftp.socket.timeout', Exception)
    def test_retry(self):
        recv_vals = [
            (b'\x00\x01test !@#\x00octet\x00', self.addr),
            tftp.socket.timeout(),
            (b'\x00\x04\x00\x01', self.addr)]
        expected_sendto = [call(b'\x00\x03\x00\x01test', self.addr)] * 2
        self.__simple_test(recv_vals, expected_sendto, read_val=b'test')

    @patch('tftp.socket.timeout', Exception)
    def test_timeout(self):
        recv_vals = [
            (b'\x00\x01test !@#\x00octet\x00', self.addr),
            tftp.socket.timeout()]
        expected_sendto = [call(b'\x00\x03\x00\x01',
                                self.addr)] * (tftp.MAX_RETRIES + 1)
        self.path_instance.joinpath().exists.return_value = True
        self.__simple_test(recv_vals, expected_sendto, read_val=b'',
                           expected_exception=tftp.TFTPException)
