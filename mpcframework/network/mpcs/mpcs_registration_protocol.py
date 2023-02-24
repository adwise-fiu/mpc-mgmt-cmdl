from ..registration_protocol import RegistrationProtocol


class MPCSRegistrationProtocol(RegistrationProtocol):

    def __init__(self):
        super().__init__()
        self.nodeinfo.attrs = {
            'location': 'Oregon',
            'cpus': 8,
            'ram': 8,
        }
        self.nodeinfo.role = 'MPCS'
