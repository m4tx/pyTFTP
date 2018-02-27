import argparse
from pathlib import Path
from typing import Callable


def path_type(check_dir=False) -> Callable[[str], str]:
    """Return a function that checks if given path exists.

    :param check_dir: if True, check if the path provided is a directory;
        False otherwise
    :return: function that checks if given path exists. Returns given parameter
        if so, and raises argparse.ArgumentTypeError if not.
    """

    def check_path(path_str: str) -> str:
        path = Path(path_str)
        if not path.exists():
            raise argparse.ArgumentTypeError(
                'Path does not exist: {}'.format(path_str))
        elif check_dir and not path.is_dir():
            raise argparse.ArgumentTypeError(
                'Path is not a directory: {}'.format(path_str))
        return path_str

    return check_path
