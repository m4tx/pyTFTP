#!/usr/bin/env python3

import argparse
import logging

import argparse_utils
from tftp import TFTPServer


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='Trivial File Transfer Protocol (TFTP) server.')
    parser.add_argument('root_dir',
                        type=argparse_utils.path_type(check_dir=True),
                        help='the root directory to serve the files from')
    parser.add_argument('-H', '--host', default='0.0.0.0',
                        help='host to listen to (default: 0.0.0.0)')
    parser.add_argument('-p', '--port', type=int, default=69,
                        help='port to listen to (default: 69)')
    parser.add_argument('-u', '--allow-upload', action='store_true',
                        help='allow uploading files')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='don\'t print incoming connections info')
    return parser


def main():
    args = create_parser().parse_args()
    logging_level = logging.INFO
    if args.quiet:
        logging_level = logging.WARNING
    logging.basicConfig(level=logging_level)

    with TFTPServer(args.host, args.port, args.root_dir,
                    args.allow_upload) as server:
        server.serve()


if __name__ == '__main__':
    main()
