import signal
import logging

logger = logging.getLogger(__name__)

def setup_signal_handler(app, logger):
    def signal_handler(sig, frame):
        logger.info("Received SIGINT, exiting...")
        app.stop()
        for handler in logger.handlers[:]:
            handler.close()
            logger.removeHandler(handler)
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, signal_handler)
    logger.debug("Signal handler set up for SIGINT")
