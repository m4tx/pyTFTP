#!/usr/bin/env python3

import argparse
from pathlib import PurePosixPath, Path

import argparse_utils
from tftp import TFTPClient, BLOCK_SIZE


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='Trivial File Transfer Protocol (TFTP) client.')
    parser.add_argument('host',
                        help='hostname/IP of the server to connect to')
    parser.add_argument('port', type=int, default=69, nargs='?',
                        help='port of the server (default: 69)')

    operation_group = parser.add_mutually_exclusive_group(required=True)
    operation_group.add_argument(
        '-g', '--get', metavar='FILE_NAME',
        help='name of the file to download')
    operation_group.add_argument(
        '-p', '--put', metavar='FILE_NAME', type=argparse_utils.path_type(),
        help='name of the file to upload')
    parser.add_argument(
        '-t', '--target', metavar='FILE_NAME',
        help='target file name (remote file name for PUT and local for GET). '
             'Default: the same as the name of the file downloaded/uploaded.')
    parser.add_argument(
        '-b', '--block-size', metavar='BLOCK_SIZE', type=int,
        default=BLOCK_SIZE,
        help='block size as defined in RFC 2348 (default: 512)')
    parser.add_argument(
        '-w', '--window-size', metavar='WINDOW_SIZE', type=int, default=1,
        help='window size as defined in RFC 7440 (default: 1)')
    return parser


def main():
    args = create_parser().parse_args()

    with TFTPClient(args.host, args.port, args.block_size,
                    args.window_size) as client:
        path = args.target
        if args.get:
            if path is None:
                path = PurePosixPath(args.get).name
            Path(path).write_bytes(client.get_file(args.get))
        elif args.put:
            if path is None:
                path = Path(args.put).name
            client.put_file(path, Path(args.put).read_bytes())


if __name__ == '__main__':
    main()
