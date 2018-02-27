import errno
import logging
import socket
from pathlib import Path, PurePosixPath
from threading import Thread
from typing import List, NewType, Tuple, Union, Dict

logger = logging.getLogger('tftpd')

BLOCK_SIZE = 512
BUF_SIZE = 65536
TIMEOUT = 0.5
MAX_RETRIES = 10


class TFTPOpcodes:
    """Class containing all the opcodes used in TFTP."""
    RRQ = b'\x00\x01'
    WRQ = b'\x00\x02'
    DATA = b'\x00\x03'
    ACK = b'\x00\x04'
    ERROR = b'\x00\x05'
    OACK = b'\x00\x06'


class TFTPErrorCodes:
    """Class containing all the error codes and their messages used in TFTP."""
    UNKNOWN = 0
    FILE_NOT_FOUND = 1
    ACCESS_VIOLATION = 2
    DISK_FULL = 3
    ILLEGAL_OPERATION = 4
    UNKNOWN_TRANSFER_ID = 5
    FILE_EXISTS = 6
    NO_SUCH_USER = 7
    INVALID_OPTIONS = 8

    __MESSAGES = {
        UNKNOWN: '',
        FILE_NOT_FOUND: 'File not found',
        ACCESS_VIOLATION: 'Access violation',
        DISK_FULL: 'Disk full or allocation exceeded',
        ILLEGAL_OPERATION: 'Illegal TFTP operation',
        UNKNOWN_TRANSFER_ID: 'Unknown transfer ID',
        FILE_EXISTS: 'File already exists',
        NO_SUCH_USER: 'No such user',
        INVALID_OPTIONS: 'Invalid options specified',
    }

    @classmethod
    def get_message(cls, error_code: int) -> str:
        """Return an error message for given error code.

        :param error_code: error code to get the message for
        :return: error message
        """
        return cls.__MESSAGES[error_code]


class TFTPOptions:
    # RFC 2348
    BLKSIZE = b'blksize'
    # RFC 7440
    WINDOWSIZE = b'windowsize'


Address = NewType('Address', tuple)
Packet = NewType('Packet', Tuple[bytes, Address])


class TFTPException(Exception):
    """Generic TFTP exception."""
    pass


class TFTPError(TFTPException):
    """Exception meaning that a TFTP ERROR packet received."""

    def __init__(self, error_id: int, message: str) -> None:
        super(TFTPError, self).__init__(
            'Error {}: {}'.format(error_id, message))
        self.error_id = error_id
        self.message = message


class TFTPTerminatedError(TFTPException):
    """Exception meaning that the TFTP connection was terminated for the
    reason passed in `error_id` and `message` arguments."""

    def __init__(self, error_id: int, error_message: str,
                 message: str) -> None:
        super(TFTPTerminatedError, self).__init__(
            'Terminated with error {}: {}; cause: {}'.format(
                error_id, error_message, message))
        self.error_id = error_id
        self.error_message = message
        self.message = message


class TFTP:
    """
    Base class for writing TFTP clients and servers. Handles all the basic
    communication: generic method for sending and receiving packets, methods
    for transmitting specific packets and whole files, as well as error
    and timeout handling.
    """

    def __init__(self, sock: socket.socket, addr: Address,
                 block_size: int = BLOCK_SIZE, window_size: int = 1) -> None:
        """
        :param sock: socket to use to communicate
        :param addr: address (host + port) of the connected host
        """
        self._sock = sock
        self._sock.settimeout(TIMEOUT)
        self._addr = addr
        self._block_size = block_size  # RFC 2348
        self._window_size = window_size  # RFC 7440
        # Whether to check the TID of incoming packets. If set to False, the
        # next packet received will be used to set the new TID (and this will
        # set _check_addr back to True)
        self._check_addr = True
        self.__last_packet: Packet = None
        self.__packet_buffer: Packet = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._sock.close()

    ###########################################################################
    # Error handling
    ###########################################################################
    def _check_error(self, data: bytes, expected_opcodes: List[bytes]) -> None:
        """Check if the packet received has valid opcode and terminate the
        connection if not or an ERROR packet was received.

        :param data: the packet received
        :param expected_opcodes: list of valid opcodes
        :raise: TFTPTerminatedError if the opcode was not valid
        :raise: TFTPError if an ERROR packet was received
        """
        opcode = data[0:2]
        if opcode == TFTPOpcodes.ERROR:
            raise TFTPError(
                int.from_bytes(data[2:4], byteorder='big'),
                data[4:-1].decode('utf-8'))
        elif opcode not in expected_opcodes:
            self._terminate(TFTPErrorCodes.ILLEGAL_OPERATION,
                            'Invalid packet: {}'.format(data))

    def _terminate(self, error_code: int, message: str,
                   error_message: str = None) -> None:
        """Send an ERROR packet, terminate the connection, and raise
        a TFTPTerminatedError

        :param error_code: error code to send
        :param message: message to use for the exception
        :param error_message: message to send with the ERROR packet. If None,
            a default message for the given error code is used.
        :raise: TFTPTerminatedError
        """
        error_message = self._error_occurred(error_code, error_message)
        self._sock.close()
        raise TFTPTerminatedError(error_code, error_message, message)

    def _error_occurred(self, error_code: int, error_message: str = None,
                        addr: Address = None) -> str:
        """Send an ERROR packet, auto-generating the message if necessary.

        :param error_code: error code to send
        :param error_message: message to send with the ERROR packet. If None,
            a default message for the given error code is used.
        :param addr: the address to send the packet to
        :return: the error message that was sent
        """
        if error_message is None:
            error_message = TFTPErrorCodes.get_message(error_code)
        self._send_err(error_code, error_message, addr)
        return error_message

    ###########################################################################
    # Receiving
    ###########################################################################
    def _set_packet_buffer(self, data: bytes, addr: Address) -> None:
        """Set given packet as the "packet buffer". Packets in the buffer have
        priority when trying to retrieve data using _recv(), giving a way to
        use data from a different source (e.g. recvfrom() executed in another
        function) when receiving a packets using a unified function.

        :param data: data to be set in the buffer
        :param addr: address to be set in the buffer
        """
        self.__packet_buffer = Packet((data, addr))

    def _recv(self, handle_timeout: bool = True) -> Packet:
        """Receive a packet, taking into account packets in the packet buffer,
        and retrying (by resending the last sent packet) if needed.

        :return: packet received
        :raise: TFTPException on timeout
        """
        if self.__packet_buffer is not None:
            rv = self.__packet_buffer
            self.__packet_buffer = None
            return rv

        if not handle_timeout:
            r = self._sock.recvfrom(BUF_SIZE)
            return r

        retries = 0
        while retries <= MAX_RETRIES:
            try:
                r = self._sock.recvfrom(BUF_SIZE)
                return r
            except socket.timeout:
                retries += 1
                if retries <= MAX_RETRIES:
                    self.__resend_last_packet()
        raise TFTPException('Timed out')

    def _recv_packet_mul(
            self, opcodes: List[bytes],
            min_data_length: int, handle_timeout: bool = True) -> Tuple[
        Address, bytes, bytes]:
        """Receive a packet and check if its opcode, length, and TID are valid.

        :param opcodes: list of valid opcodes
        :param min_data_length: minimum valid length of the data
        :param check_addr: True if TID validity should be checked; False
            otherwise
        :return: a 3-tuple containing: source packet address, opcode received
            and the data
        """
        while True:
            data, addr = self._recv(handle_timeout)
            if not self._check_addr or addr == self._addr:
                break
            logger.warning('Invalid TID: %s (expected: %s)', addr, self._addr)
            self._error_occurred(TFTPErrorCodes.UNKNOWN_TRANSFER_ID, addr=addr)

        if not self._check_addr:
            self._addr = addr
            self._check_addr = True

        self._check_error(data, opcodes)
        if len(data) < min_data_length + 2:
            self._terminate(TFTPErrorCodes.ILLEGAL_OPERATION,
                            'Packet too short: {}'.format(data))
        return addr, data[0:2], data[2:]

    def _recv_packet(self, opcode: bytes, min_data_length: int,
                     handle_timeout: bool = True) -> Tuple[Address, bytes]:
        """Receive a packet and check if its opcode, length, and TID are valid.

        :param opcode: valid opcode
        :param min_data_length: minimum valid length of the data
        :return: a pair containing: source packet address and the data received
        """
        addr, _, data = self._recv_packet_mul([opcode], min_data_length,
                                              handle_timeout)
        return addr, data

    def _recv_data(
            self, handle_timeout: bool = True) -> Tuple[Address, bytes, bytes]:
        """Receive a DATA packet and return the block ID and the data.

        :return: 3-tuple containing the source address, block ID, and the data
        """
        addr, data = self._recv_packet(TFTPOpcodes.DATA, 2, handle_timeout)
        return addr, data[0:2], data[2:]

    def _recv_ack(self, handle_timeout: bool = True) -> Tuple[Address, int]:
        """Receive an ACK packet and return the block ID.

        :return: pair containing the source address and the block ID
        """
        addr, data = self._recv_packet(TFTPOpcodes.ACK, 2, handle_timeout)
        return addr, int.from_bytes(data, byteorder='big')

    ###########################################################################
    # Sending
    ###########################################################################
    def _send(self, data: bytes, addr: Address = None) -> None:
        """Send a packet and store it as the last packet sent.

        :param data: data to be sent
        :param addr: the destionation address to send the packet to. If None,
            self._addr is used.
        """
        if addr is None:
            addr = self._addr
        self.__last_packet = Packet((data, addr))
        self._sock.sendto(data, addr)

    def __resend_last_packet(self) -> None:
        """Resend the last packet received (used for retries in _recv())."""
        self._sock.sendto(*self.__last_packet)

    def _send_ack(self, block_id: Union[bytes, int]) -> None:
        """Send an ACK packet.

        :param block_id: block ID to send
        """
        if isinstance(block_id, int):
            block_id = block_id.to_bytes(2, byteorder='big')
        self._send(TFTPOpcodes.ACK + block_id)

    def _send_data(self, block_id: int, data: bytes) -> None:
        """Send a DATA packet.

        :param block_id: block ID of the data
        :param data: the data to send
        """
        self._send(
            TFTPOpcodes.DATA + block_id.to_bytes(2, byteorder='big') + data)

    def _send_err(self, error_code: int, error_message: str = None,
                  addr: Address = None) -> None:
        """Send an ERROR packet.

        :param error_code: error code to send
        :param error_message: error message to send
        :param addr: the desitination address to send the packet to
        """
        error_code_bytes = error_code.to_bytes(2, byteorder='big')
        error_message_bytes = error_message.encode('utf-8')

        self._send(TFTPOpcodes.ERROR + error_code_bytes + error_message_bytes +
                   b'\x00', addr)

    ###########################################################################
    # Options (RFC 2347)
    ###########################################################################
    def _process_options(self, options: List[bytes]) -> Dict[bytes, bytes]:
        """Process the options received in RRQ/WRQ packet.

        This is an implementation of the RFC 2347 Options Extension.

        :param options: list of the option strings (null-separated in
            the original packet)
        :return: dictionary of the processed and accepted options
        """
        if options[-1] == b'':
            options.pop()

        if len(options) % 2 == 1:
            raise ValueError

        ret_val = {}
        vals = zip(options[::2], options[1::2])
        d = {k.lower(): (k, v) for k, v in vals}

        # Block size (RFC 2348)
        if TFTPOptions.BLKSIZE in d:
            orig_key, orig_val = d[TFTPOptions.BLKSIZE]
            blk_size = int(orig_val)
            if blk_size < 8 or blk_size > 65464:
                # Invalid according to RFC 2348
                raise ValueError
            self._block_size = blk_size
            ret_val[orig_key] = orig_val

        # Window size (RFC 7440)
        if TFTPOptions.WINDOWSIZE in d:
            orig_key, orig_val = d[TFTPOptions.WINDOWSIZE]
            window_size = int(orig_val)
            if window_size < 1 or window_size > 65535:
                # Invalid according to RFC 7440
                raise ValueError
            self._window_size = window_size
            ret_val[orig_key] = orig_val

        return ret_val

    def _format_options(self, options: Dict[bytes, bytes]):
        """Create single options bytes object out of the provided dictionary.

        :param options: dictionary to convert to bytes object
        :return: generated bytes object
        """
        return b''.join(b'%s\x00%s\x00' % option for option in options.items())

    ###########################################################################
    # Files
    ###########################################################################
    def _recv_file(self) -> bytes:
        """Receive a file by listening for DATA packets and responding
        with ACKs.

        :return: received file
        """
        last_id = 0
        parts = []

        retries = 0
        while retries <= MAX_RETRIES:
            start_last_id = last_id
            for _ in range(self._window_size):
                try:
                    addr, block_id, data = self._recv_data(
                        handle_timeout=False)

                    id_int = int.from_bytes(block_id, byteorder='big')
                    if id_int == last_id + 1:
                        parts.append(data)
                        last_id = id_int

                        if block_id == b'\xff\xff':
                            last_id = -1

                        if len(data) < self._block_size:
                            self._send_ack(last_id)
                            return b''.join(parts)
                except socket.timeout:
                    if last_id == start_last_id:
                        retries += 1
                        break
                    else:
                        retries = 0

            if retries <= MAX_RETRIES:
                self._send_ack((65535 if last_id == -1 else last_id))

        raise TFTPException('Timed out')

    def _send_file(self, data: bytes) -> None:
        """Send a file by sending DATA packets and listening for ACKs.

        :param data: data to be sent
        """
        outer_block_id = 0
        block_id = 0

        while True:
            retries = 0
            while retries <= MAX_RETRIES:
                try:
                    if not self.__send_blocks(data, outer_block_id, block_id):
                        return

                    _, ack_block_id = self._recv_ack(handle_timeout=False)
                    last_block_id = block_id + self._window_size
                    if ((last_block_id >= ack_block_id >= block_id) or
                            (ack_block_id <= last_block_id % 65536 and
                             ack_block_id < block_id)):
                        # If received ACK is a reply to one of the blocks sent
                        # sent the next batch of blocks, else re-send
                        if ack_block_id < block_id:
                            outer_block_id += 1
                        block_id = ack_block_id
                    break
                except socket.timeout:
                    retries += 1
            else:
                raise TFTPException('Timed out')

    def __send_blocks(
            self, data: bytes, outer_block_id: int, inner_block_id: int):
        """Send a single window of data.

        :param data: data to be sent
        :param outer_block_id: starting "outer" block ID (incremented by 1
            each time inner block ID overflows)
        :param inner_block_id: starting "inner" block ID in the range [0, 65535]
        :return: False if there is no data to be sent; True otherwise
        """
        blk_size = self._block_size

        for i in range(self._window_size):
            local_blkid = outer_block_id * 65536 + inner_block_id + i
            if local_blkid * self._block_size > len(data):
                if i == 0:
                    return False
                else:
                    break

            to_send = data[local_blkid * blk_size:
                           (local_blkid + 1) * blk_size]
            self._send_data((local_blkid + 1) % 65536, to_send)

        return True


class TFTPClient(TFTP):
    """
    Class that handles communication with a TFTP server and allows to download
    and upload files.
    """

    def __init__(self, host: str, port: int,
                 block_size: int = BLOCK_SIZE, window_size: int = 1) -> None:
        """
        :param host: hostname/IP of the server to connect to
        :param port: UDP port of the server to connect to
        :param block_size: block size, as in RFC 2347
        :param window_size: window size, as in RFC 7440
        """
        super(TFTPClient, self).__init__(
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM),
            Address((host, port)), block_size, window_size)
        self.__options = self._format_options(self.__create_options_dict())

    def __create_options_dict(self) -> Dict[bytes, bytes]:
        """Create options dictionary to feed into TFTP._format_options method.

        The method omits the options that have default value.

        :return: generated dictionary
        """
        d = {}

        if self._block_size != BLOCK_SIZE:
            d[TFTPOptions.BLKSIZE] = str(self._block_size).encode('utf-8')
        if self._window_size != 1:
            d[TFTPOptions.WINDOWSIZE] = str(self._window_size).encode('utf-8')

        return d

    def __send_rq(self, opcode: bytes, file_name: str,
                  mode: str = 'octet') -> None:
        """Send an RRQ/WRQ packet.

        :param opcode: opcode to send (see TFTPOpcodes.RRQ and TFTPOpcodes.WRQ)
        :param file_name: name of the file requested
        :param mode: requested file transfer mode ('octet' by default)
        """
        self._send(b'%s%s\x00%s\x00%s' % (
            opcode, bytes(file_name, 'utf-8'), bytes(mode, 'utf-8'),
            self.__options))

    def __send_rrq(self, file_name: str, mode: str = 'octet') -> None:
        """Send an RRQ packet.

        :param file_name: name of the file requested
        :param mode: requested file transfer mode ('octet' by default)
        """
        self.__send_rq(TFTPOpcodes.RRQ, file_name, mode)

    def __send_wrq(self, file_name: str, mode: str = 'octet') -> None:
        """Send a WRQ packet.

        :param file_name: name of the uploaded file
        :param mode: requested file transfer mode ('octet' by default)
        """
        self.__send_rq(TFTPOpcodes.WRQ, file_name, mode)

    def get_file(self, file_name: str) -> bytes:
        """Retrieve a file from the connected server.

        :param file_name: name of the file to download
        :return: file data returned by the server
        """
        self.__send_rrq(file_name)
        self._check_addr = False
        self.__recv_first_rrq_packet()
        return self._recv_file()

    def __recv_first_rrq_packet(self):
        """Receive and respond (in case of OACK) to the first packet after
        sending RRQ - either OACK or DATA.
        """
        addr, opcode, data = self._recv_packet_mul(
            [TFTPOpcodes.OACK, TFTPOpcodes.DATA], 0)
        if opcode == TFTPOpcodes.DATA:
            self._set_packet_buffer(opcode + data, addr)
        else:
            self.__process_oack(data)
            self._send_ack(b'\x00\x00')

    def put_file(self, file_name: str, data: bytes) -> None:
        """Upload a file to the connected server.

        :param file_name: name of the uploaded file
        :param data: data to be sent
        """
        self.__send_wrq(file_name)
        self._check_addr = False
        self.__recv_first_wrq_packet()
        self._send_file(data)

    def __recv_first_wrq_packet(self):
        """Receive the first packet after sending WRQ - either OACK or ACK."""
        addr, opcode, data = self._recv_packet_mul(
            [TFTPOpcodes.OACK, TFTPOpcodes.ACK], 0)
        if opcode == TFTPOpcodes.OACK:
            self.__process_oack(data)

    def __process_oack(self, data: bytes):
        """Process and apply the options from the OACK packet.

        :param data: raw data got from the packet
        """
        self._process_options(data.split(b'\0'))


class TFTPClientHandler(TFTP):
    """
    Class that handles the communication with a single TFTP client on the
    server side.
    """

    def __init__(self, host: str, addr: Address, root_dir: Path,
                 allow_upload: bool, initial_buffer: bytes = None) -> None:
        """
        :param host: host of the server to bind to
        :param addr: address of the client to connect with
        :param root_dir: root directory of the files to serve
        :param allow_upload: whether or not allow to upload files
        :param initial_buffer: initial packet buffer; usually a `bytes` object
            containing the first (RRQ/WRQ) packet, or None, if there is no
            external server that catches the first packet.
        """
        super().__init__(
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM), addr)

        if initial_buffer is not None:
            self._set_packet_buffer(initial_buffer, self._addr)

        self._sock.bind((host, 0))
        logger.info('Incoming connection from %s, binding at: %s',
                    self._addr, self._sock.getsockname())

        self.__root_dir = root_dir
        self.__allow_upload = allow_upload

    def handle_client(self) -> None:
        """Handle the request sent by the connected client."""
        opcode, file_name, mode = self.__recv_rq()
        try:
            path = self.__get_file_path(file_name)
            if opcode == TFTPOpcodes.RRQ:
                self.__handle_rrq(path)
            else:
                self.__handle_wrq(path)
        except OSError as e:
            self.__handle_file_error(e)

    def __exit__(self, exc_type, exc_val, exc_tb):
        logger.info('Closing connection to %s, bound at: %s',
                    self._addr, self._sock.getsockname())
        super(TFTPClientHandler, self).__exit__(exc_type, exc_val, exc_tb)

    def __recv_rq(self) -> Tuple[bytes, str, str]:
        """Receive an RRQ/WRQ packet and return received data.

        :return: 3-tuple containing: received opcode, file name and file
            transfer mode
        """
        _, opcode, data = self._recv_packet_mul(
            [TFTPOpcodes.RRQ, TFTPOpcodes.WRQ], 2)

        try:
            file_name_bytes, mode_bytes, *options = data.split(b'\0')
            try:
                new_options = self._process_options(options)
                if len(new_options):
                    self.__send_oack(new_options)
                    if opcode == TFTPOpcodes.RRQ:
                        self._recv_ack()
            except ValueError:
                self._terminate(TFTPErrorCodes.INVALID_OPTIONS,
                                'Invalid options received')

            file_name = file_name_bytes.decode('utf-8')
            mode = mode_bytes.decode('utf-8')
        except ValueError as e:
            self._terminate(TFTPErrorCodes.ILLEGAL_OPERATION, str(e))
        if mode != 'octet':
            self._terminate(TFTPErrorCodes.ILLEGAL_OPERATION,
                            'Mode is not "octet": {}'.format(mode))

        return opcode, file_name, mode

    def __send_oack(self, new_options: Dict[bytes, bytes]):
        """Send an OACK packet.

        :param new_options: dictionary of options to be included in
            the OACK packet.
        """
        msg = TFTPOpcodes.OACK + self._format_options(new_options)
        self._send(msg)

    def __get_file_path(self, file_name: str) -> Path:
        """Return file path inside server root directory, ignoring "evil"
        paths, like "../../secret_file", "/etc/fstab", etc.

        :param file_name: file name to get the path to
        :return: absolute path inside the server root directory
        """
        while PurePosixPath(file_name).is_absolute():
            file_name = file_name[1:]
        path = self.__root_dir.joinpath(file_name)

        try:
            path.relative_to(self.__root_dir)
        except ValueError:
            self._terminate(TFTPErrorCodes.ACCESS_VIOLATION,
                            'Invalid path: {}'.format(file_name))
        return path

    def __handle_rrq(self, path: Path) -> None:
        """Handle RRQ request: read and send the requested file.

        :param path: path to the requested file
        """
        self._send_file(path.read_bytes())

    def __handle_wrq(self, path: Path) -> None:
        """Handle WRQ request: download and save the file from the client,
        taking into account the `__allow_upload` setting.

        :param path: path to save the file as
        """
        if not self.__allow_upload:
            self._terminate(TFTPErrorCodes.ACCESS_VIOLATION,
                            'Upload not allowed')
        if path.exists():
            self._terminate(TFTPErrorCodes.FILE_EXISTS,
                            'File exists: {}'.format(path))

        self._send_ack(b'\x00\x00')
        path.write_bytes(self._recv_file())

    def __handle_file_error(self, e: OSError) -> None:
        """Handle given IO error, sending an appropriate ERROR packet and
        terminating the transmission.

        :param e: error raised when trying to open the file
        """
        error_message = None
        if e.errno == errno.ENOENT:
            error_code = TFTPErrorCodes.FILE_NOT_FOUND
        elif e.errno == errno.EPERM or e.errno == errno.EACCES:
            error_code = TFTPErrorCodes.ACCESS_VIOLATION
        elif e.errno == errno.EFBIG or e.errno == errno.ENOSPC:
            error_code = TFTPErrorCodes.DISK_FULL
        else:
            error_code = TFTPErrorCodes.UNKNOWN
            error_message = e.strerror
        self._terminate(error_code, e.strerror, error_message)


class TFTPServer:
    """
    Class that handles communication with multiple TFTP clients. Uses
    TFTPClientHandler for the communication with each single client, running
    one instance of this class in a separate thread for each client.
    """

    def __init__(self, host: str, port: int, root_dir: Union[str, Path],
                 allow_upload: bool) -> None:
        """
        :param host: host of the server to bind to
        :param port: port to bind to
        :param root_dir: the directory where the files should be served from
        :param allow_upload: whether or not allow uploading new files
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        addr = (host, port)
        logger.info('Starting TFTP server, listening on %s', addr)
        self.sock.bind(addr)

        self.host = host
        self.root_dir = Path(root_dir)
        self.allow_upload = allow_upload

    def __enter__(self):
        return self

    def serve(self) -> None:
        """Run the main server loop: wait for new connections and run
        TFTPClientHandler for each.
        """
        while True:
            data, addr = self.sock.recvfrom(BUF_SIZE)

            def handle_client() -> None:
                TFTPClientHandler(
                    self.host, addr, self.root_dir, self.allow_upload,
                    data).handle_client()

            Thread(target=handle_client).start()

    def __exit__(self, exc_type, exc_val, exc_tb):
        logger.info('Stopping TFTP server')
        self.sock.close()
