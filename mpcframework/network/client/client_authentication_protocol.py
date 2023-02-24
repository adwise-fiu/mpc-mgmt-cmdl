from ..authentication_protocol import AuthenticationProtocol


class ClientAuthenticationProtocol(AuthenticationProtocol):

    def __init__(self, *args):
        super().__init__(*args)
        self.nodeinfo['role'] = 'CLIENT'
