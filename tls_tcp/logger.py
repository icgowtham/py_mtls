"""Logger module."""

import logging

__author__ = 'Ishwarachandra Gowtham'
__email__ = 'ic.gowtham@gmail.com'
__version__ = '1.0'


def get_logger(level=logging.DEBUG):
    """
    Custom logger.

    :param level: int
        The logging level indicator.
    :return: object
        logging.get_logger() object.
    """
    logger = logging.getLogger()
    # Work as a stand-alone logger when other loggers are not available.
    if not logger.handlers:
        formatter = logging.Formatter(
            '[%(asctime)s]: %(name)s: %(levelname)s: %(message)s : %(filename)s#%(lineno)d %(funcName)s')
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        handler.setLevel(level)
        logger.addHandler(handler)
    # Disable duplicate logging. https://docs.python.org/2/library/logging.html#logger-objects
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    return logger
