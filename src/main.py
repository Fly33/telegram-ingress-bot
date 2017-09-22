# -*- coding: utf8 -*-
import logging
import logging.handlers
import traceback
from argparse import ArgumentParser

from config import Config
from telegram import Telegram


TRACE = 5


def main():
    parser = ArgumentParser()
    parser.add_argument("-c", "--config", help="yaml config file name", default="config.yaml")
    args = parser.parse_args()

    config = Config()
    try:
        config.load(args.config)
    except:
        logging.error('Unable to open "{}" file.'.format(options.config))
        return

    level = TRACE
    logging.addLevelName(TRACE, "TRACE")
    logger = logging.getLogger()
    logger.setLevel(level)
    formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    handler = logging.handlers.RotatingFileHandler(config["log"], maxBytes=16000000, backupCount=2)
    handler.setLevel(level)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    handler.setLevel(level)
    logger.addHandler(handler)

    telegram = Telegram(config['telegram'])
    telegram.Run()


if __name__ == "__main__":
    main()
