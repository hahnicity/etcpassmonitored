#
# Default configuration for etcpassmonitored. To enable new configuration you have
# the option of creating an override file and specifying its path with the
# ETCPASSMONITORED_CONFIG envvar.
#
import os


NOTIFY_MODULE = os.path.join(os.path.dirname(__file__), "varlog.py")
