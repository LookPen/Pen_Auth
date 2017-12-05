from django.conf import settings

USER_SETTINGS = getattr(settings, 'OAUTH2_PROVIDER', None)  # 允许用户配置 覆盖默认的配置

DEFAULTS = {
    'ROTATE_REFRESH_TOKEN': True,  # 刷新token时 是否使用新的的token字符串
    'AUTHORIZATION_CODE_EXPIRE_SECONDS': 60,  # Code 过期时间 单位 秒
    'ACCESS_TOKEN_EXPIRE_SECONDS': 36000,  # token 过期时间 单位 秒
}


class OAuth2ProviderSettings:
    def __init__(self, user_settings=None, defaults=None):
        self.user_settings = user_settings or {}
        self.defaults = defaults or {}

    def __getattr__(self, item):
        if item not in self.defaults.keys():
            raise AttributeError('未定义{0}'.format(item))

        try:
            value = self.user_settings[item]  # 用户配置的优先
        except:
            value = self.defaults[item]

        setattr(self, item, value)

        return value


oauth2_settings = OAuth2ProviderSettings(USER_SETTINGS, DEFAULTS)
