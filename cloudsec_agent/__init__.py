__all__ = ["main"]


def main(argv=None):
    from .floci_probe import main as _main

    return _main(argv)