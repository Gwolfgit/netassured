# Pyrewall Main
import os

from loguru import logger

from pyrewall.core.firewall import IPTables
from pyrewall.core.dyndns import DynDns

if os.geteuid() != 0:
    logger.error("Program must be run as root!")
    exit(1)


#ipt = IPTables()
dyn = DynDns()
dyn.get_latest()
dyn.remove_old()



