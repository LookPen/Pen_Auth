from oauth_pen.setting import oauth2_settings


class OAuthCore:
    def __init__(self,server=None):
        self.server = server or oauth2_settings.OAUTH2_SERVER_CLASS(oauth2_settings.OAUTH2_VALIDATOR_CLASS())
