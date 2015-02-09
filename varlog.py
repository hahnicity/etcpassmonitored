import logging

# Define our global logger.
logger = logging.getLogger("etcpassmonitored")
handler = logging.FileHandler('/var/log/etcpassmonitored.log')
formatter = logging.Formatter('%(asctime)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)


def notify(reason):
    logger.warn(reason)
