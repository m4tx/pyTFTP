from typing import List, Tuple
from unittest.mock import patch, call, _Call

import tftp
from tests.tftp_test_case import TFTPTestCase


class TestTFTPClient(TFTPTestCase):
    def setUp(self):
        super(TestTFTPClient, self).setUp()
        self.client = tftp.TFTPClient(*self.srv_addr)
        self.client.__enter__()

    def tearDown(self):
        self.client.__exit__(None, None, None)
        super(TestTFTPClient, self).tearDown()

    def test_setup(self):
        self.socket.socket.assert_called_with(
            self.socket.AF_INET, self.socket.SOCK_DGRAM)

    def __simple_test(
            self, recv_values: List[tftp.Packet], func: str, args: Tuple,
            expected_sendto: List[_Call], expected_data: bytes = None) -> None:
        """Test GET/PUT operation without expecting any errors.

        :param recv_values: list of values that should be returned by recvfrom()
        :param func: function to use: 'get' or 'put'
        :param args: arguments for the function
        :param expected_sendto: expected packets sent (as a list of arguments
            for the sendto() function)
        :param expected_data: expected data to be returned by GET
        """
        self.socket_instance.recvfrom.side_effect = recv_values
        assert func in ['get', 'put']
        data = None
        if func == 'get':
            data = self.client.get_file(*args)
        elif func == 'put':
            self.client.put_file(*args)

        self.assertEqual(
            expected_sendto, self.socket_instance.sendto.call_args_list)
        if func == 'get':
            self.assertEqual(expected_data, data)

    def test_get_empty_file(self):
        expected_sendto = [
            call(b'\x00\x01test !@#\x00octet\x00', self.srv_addr),
            call(b'\x00\x04\x00\x01', self.addr)]
        self.__simple_test(
            [(b'\x00\x03\x00\x01', self.addr)], 'get', ('test !@#',),
            expected_sendto, b'')

    def test_get_empty_file_random_blockid(self):
        recv_values = [
            (b'\x00\x03\xca\xfe', self.addr),
            (b'\x00\x03\x00\x01', self.addr)]
        expected_sendto = [
            call(b'\x00\x01test\x00octet\x00', self.srv_addr),
            call(b'\x00\x04\x00\x00', self.addr),
            call(b'\x00\x04\x00\x01', self.addr)]
        self.__simple_test(
            recv_values, 'get', ('test',),
            expected_sendto, b'')

    def test_get_short_file(self):
        expected_sendto = [
            call(b'\x00\x01test\x00octet\x00', self.srv_addr),
            call(b'\x00\x04\x00\x01', self.addr)]
        self.__simple_test(
            [(b'\x00\x03\x00\x01test contents', self.addr)], 'get', ('test',),
            expected_sendto, b'test contents')

    def test_get_long_file(self):
        recv_values = [
            (b'\x00\x03\x00\x01' + b'a' * 512, self.addr),
            (b'\x00\x03\x00\x02' + b'a' * 511, self.addr)]
        expected_sendto = [
            call(b'\x00\x01test\x00octet\x00', self.srv_addr),
            call(b'\x00\x04\x00\x01', self.addr),
            call(b'\x00\x04\x00\x02', self.addr)]
        self.__simple_test(
            recv_values, 'get', ('test',),
            expected_sendto, b'a' * 1023)

    def test_get_huge_file(self):
        recv_values = []
        expected_sendto = [
            call(b'\x00\x01test\x00octet\x00', self.srv_addr)]

        for i in range(1, 65537):
            block_id = (i % 65536).to_bytes(2, byteorder='big')
            recv_values.append(
                (b'\x00\x03' + block_id +
                 b'a' * (0 if i == 65536 else 512), self.addr))
            expected_sendto.append(call(b'\x00\x04' + block_id, self.addr))

        self.__simple_test(recv_values, 'get', ('test',),
                           expected_sendto, b'a' * (65535 * 512))

    def test_get_with_blksize_option(self):
        self.client = tftp.TFTPClient(*self.srv_addr, 8192)
        recv_values = [
            (b'\x00\x06blksize\x008192\x00', self.addr),
            (b'\x00\x03\x00\x01' + b'a' * 8192, self.addr),
            (b'\x00\x03\x00\x02' + b'a' * 8191, self.addr)]
        expected_sendto = [
            call(b'\x00\x01test\x00octet\x00blksize\x008192\x00',
                 self.srv_addr),
            call(b'\x00\x04\x00\x00', self.addr),
            call(b'\x00\x04\x00\x01', self.addr),
            call(b'\x00\x04\x00\x02', self.addr)]
        self.__simple_test(recv_values, 'get', ('test',),
                           expected_sendto, b'a' * 16383)

    def test_get_with_windowsize(self):
        self.client = tftp.TFTPClient(*self.srv_addr, window_size=2)
        recv_values = [
            (b'\x00\x06windowsize\x002\x00', self.addr),
            (b'\x00\x03\x00\x01' + b'a' * 512, self.addr),
            (b'\x00\x03\x00\x02' + b'a' * 511, self.addr)]
        expected_sendto = [
            call(b'\x00\x01test\x00octet\x00windowsize\x002\x00',
                 self.srv_addr),
            call(b'\x00\x04\x00\x00', self.addr),
            call(b'\x00\x04\x00\x02', self.addr)]
        self.__simple_test(recv_values, 'get', ('test',),
                           expected_sendto, b'a' * 1023)

    @patch('tftp.socket.timeout', Exception)
    def test_get_with_windowsize_timeout(self):
        self.client = tftp.TFTPClient(*self.srv_addr, window_size=2)
        recv_values = [
            (b'\x00\x06windowsize\x002\x00', self.addr),
            (b'\x00\x03\x00\x01' + b'a' * 512, self.addr),
            tftp.socket.timeout(),
            (b'\x00\x03\x00\x02' + b'a' * 512, self.addr),
            (b'\x00\x03\x00\x03' + b'a' * 511, self.addr)]
        expected_sendto = [
            call(b'\x00\x01test\x00octet\x00windowsize\x002\x00',
                 self.srv_addr),
            call(b'\x00\x04\x00\x00', self.addr),
            call(b'\x00\x04\x00\x01', self.addr),
            call(b'\x00\x04\x00\x03', self.addr)]
        self.__simple_test(recv_values, 'get', ('test',),
                           expected_sendto, b'a' * 1535)

    def test_put_empty_file(self):
        recv_values = [
            (b'\x00\x04\x00\x00', self.srv_addr),
            (b'\x00\x04\x00\x01', self.srv_addr)]
        expected_sendto = [
            call(b'\x00\x02test !@#\x00octet\x00', self.srv_addr),
            call(b'\x00\x03\x00\x01', self.srv_addr)]
        self.__simple_test(
            recv_values, 'put', ('test !@#', b''), expected_sendto)

    def test_put_short_file(self):
        recv_values = [
            (b'\x00\x04\x00\x00', self.srv_addr),
            (b'\x00\x04\x00\x01', self.srv_addr)]
        expected_sendto = [
            call(b'\x00\x02test !@#\x00octet\x00', self.srv_addr),
            call(b'\x00\x03\x00\x01test contents', self.srv_addr)]
        self.__simple_test(
            recv_values, 'put', ('test !@#', b'test contents'),
            expected_sendto)

    def test_put_long_file(self):
        recv_values = [
            (b'\x00\x04\x00\x00', self.srv_addr),
            (b'\x00\x04\x00\x01', self.srv_addr),
            (b'\x00\x04\x00\x02', self.srv_addr)]
        expected_sendto = [
            call(b'\x00\x02test !@#\x00octet\x00', self.srv_addr),
            call(b'\x00\x03\x00\x01' + b'a' * 512, self.srv_addr),
            call(b'\x00\x03\x00\x02' + b'a' * 511, self.srv_addr)]
        self.__simple_test(
            recv_values, 'put', ('test !@#', b'a' * 1023), expected_sendto)

    def test_put_with_blksize_option(self):
        self.client = tftp.TFTPClient(*self.srv_addr, 8192)
        recv_values = [
            (b'\x00\x06blksize\x008192\x00', self.srv_addr),
            (b'\x00\x04\x00\x01', self.srv_addr),
            (b'\x00\x04\x00\x02', self.srv_addr)]
        expected_sendto = [
            call(b'\x00\x02test\x00octet\x00blksize\x008192\x00',
                 self.srv_addr),
            call(b'\x00\x03\x00\x01' + b'a' * 8192, self.srv_addr),
            call(b'\x00\x03\x00\x02' + b'a' * 8191, self.srv_addr)]
        self.__simple_test(
            recv_values, 'put', ('test', b'a' * 16383), expected_sendto)

    def test_tftp_error(self):
        self.socket_instance.recvfrom.return_value = (
            b'\x00\x05\x00\x01File not found\x00', self.addr)
        with self.assertRaises(tftp.TFTPError) as cm:
            self.client.get_file('test')

        self.assertEqual(1, cm.exception.error_id)
        self.assertEqual('File not found', cm.exception.message)

    def test_invalid_opcode(self):
        self.socket_instance.recvfrom.return_value = (
            b'\x00\xff\x00\x01', self.srv_addr)
        with self.assertRaises(tftp.TFTPTerminatedError):
            self.client.get_file('test')
        self.socket_instance.sendto.assert_called_with(
            b'\x00\x05\x00\x04Illegal TFTP operation\x00', self.srv_addr)
        self.socket_instance.close.assert_called()

    @patch('tftp.socket.timeout', type('timeout', (Exception,), {}))
    def test_invalid_packet_format(self):
        self.socket_instance.recvfrom.return_value = (
            b'\x00\x03\x00', self.srv_addr)
        with self.assertRaises(tftp.TFTPTerminatedError):
            self.client.get_file('test')
        self.socket_instance.sendto.assert_called_with(
            b'\x00\x05\x00\x04Illegal TFTP operation\x00', self.srv_addr)
        self.socket_instance.close.assert_called()

    def test_invalid_tid(self):
        evil_addr = ('evil.addr.com', 666)
        recv_values = [
            (b'\x00\x03\x00\x01' + b'a' * 512, self.addr),
            (b'\x00\x03\x00\x02' + b'b' * 511, evil_addr),
            (b'\x00\x03\x00\x02' + b'a' * 511, self.addr)]
        expected_sendto = [
            call(b'\x00\x01test\x00octet\x00', self.srv_addr),
            call(b'\x00\x04\x00\x01', self.addr),
            call(b'\x00\x05\x00\x05Unknown transfer ID\x00', evil_addr),
            call(b'\x00\x04\x00\x02', self.addr)]
        self.__simple_test(
            recv_values, 'get', ('test',), expected_sendto, b'a' * 1023)

    @patch('tftp.socket.timeout', Exception)
    def test_retry(self):
        recv_values = [
            tftp.socket.timeout(),
            (b'\x00\x03\x00\x01' + b'a' * 512, self.addr),
            tftp.socket.timeout(),
            (b'\x00\x03\x00\x02', self.addr)]
        expected_sendto = [
            call(b'\x00\x01test !@#\x00octet\x00', self.srv_addr),
            call(b'\x00\x01test !@#\x00octet\x00', self.srv_addr),
            call(b'\x00\x04\x00\x01', self.addr),
            call(b'\x00\x04\x00\x01', self.addr),
            call(b'\x00\x04\x00\x02', self.addr)]
        self.__simple_test(
            recv_values, 'get', ('test !@#',), expected_sendto, b'a' * 512)

    @patch('tftp.socket.timeout', Exception)
    def test_timeout(self):
        self.socket_instance.recvfrom.side_effect = tftp.socket.timeout()
        with self.assertRaises(tftp.TFTPException):
            self.client.get_file('test')
        self.assertEqual(tftp.MAX_RETRIES + 1,
                         self.socket_instance.sendto.call_count)

    @patch('tftp.socket.timeout', Exception)
    def test_timeout_after_valid_data(self):
        recv_values = [
            tftp.socket.timeout(),
            (b'\x00\x03\x00\x01' + b'a' * 512, self.addr)] + [
            tftp.socket.timeout()] * (tftp.MAX_RETRIES + 1)
        expected_sendto = [
            call(b'\x00\x01test\x00octet\x00', self.srv_addr),
            call(b'\x00\x01test\x00octet\x00', self.srv_addr)] + [
            call(b'\x00\x04\x00\x01', self.addr)] * (tftp.MAX_RETRIES + 1)

        self.socket_instance.recvfrom.side_effect = recv_values
        with self.assertRaises(tftp.TFTPException):
            self.client.get_file('test')

        self.assertEqual(
            expected_sendto, self.socket_instance.sendto.call_args_list)
