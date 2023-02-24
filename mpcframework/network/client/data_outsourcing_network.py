import logging

from ..pmp_network import PmpNetwork

logger = logging.getLogger('DataOutsourcingNetwork')


class DataOutsourcingNetwork(PmpNetwork):

    def __init__(self, *args):
        super().__init__(*args)
