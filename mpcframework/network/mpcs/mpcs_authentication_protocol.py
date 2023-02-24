from ..authentication_protocol import AuthenticationProtocol


class MPCSAuthenticationProtocol(AuthenticationProtocol):

    def __init__(self, *args):
        super().__init__(*args)
        self.nodeinfo['role'] = 'MPCS'
