#!/usr/bin/python3.6
#coding: utf-8

import sys
import logging
from logging import handlers as logging_handlers

from neverland.exceptions import ConfigError


# mapping names of loggers and the keyword of their config
LOGGER_NAME_CONFIG_KW_MAPPING = {
    'Main': 'main',
    'SHM': 'shm',
}


main_logger = logging.getLogger('Main')
logger = logging.getLogger('Main')


def init_all_loggers(config):
    lv_map = {
        'debug': logging.DEBUG,
        'info': logging.INFO,
        'warn': logging.WARN,
        'error': logging.ERROR,
    }

    for logger_name, conf_kw in LOGGER_NAME_CONFIG_KW_MAPPING.items():
        logger = logging.getLogger(logger_name)
        logger_conf = getattr(config.log, conf_kw)

        level = lv_map.get(logger_conf.level) or logging.INFO
        paht = logger_conf.path
        stdout_enabled = logger_conf.stdout

        init_logger(logger, level, path, stdout_enabled)

    main_logger.info(f'Main log level: {log_level}')


def init_logger(logger, lv, log_path=None, stdout_enabled=True):
    logger.setLevel(lv)

    formatter = logging.Formatter(
        '%(asctime)s - [%(name)s] - %(levelname)s: %(message)s'
    )

    if log_path is not None:
        fh = logging_handlers.WatchedFileHandler(log_path)
        fh.setLevel(lv)
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    if stdout_enabled:
        sh = logging.StreamHandler(sys.stdout)
        sh.setLevel(lv)
        sh.setFormatter(formatter)
        logger.addHandler(sh)

    return logger
