import logging

def setup_logging():
    logger = logging.getLogger('')  # Root logger
    logger.setLevel(logging.DEBUG)
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter('%(levelname)s:%(name)s:%(message)s'))
    logger.addHandler(console_handler)
    file_handler = logging.FileHandler('n64ea.log', mode='w')
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(name)s - %(message)s'))
    logger.addHandler(file_handler)
    return logger
