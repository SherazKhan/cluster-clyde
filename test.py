import logging
import sys

logging.basicConfig()
logger = logging.getLogger('Cluster-Clyde')
logger.setLevel(logging.DEBUG)

logger.debug('Importing cluster class...')
from cclyde import Cluster

logger.debug('Initializing cluster obj...')
cluster = Cluster()

logger.debug('Printing initialized cluster obj...\n')
print cluster

logger.debug('Printing keys...\n')
print cluster.aws_keys



logger.debug('Exiting...\n')
sys.exit(0)