from urllib.parse import urlsplit

from django.core.validators import RegexValidator
from django.core.exceptions import ValidationError


class RedirectURIValidator(RegexValidator):
    def __init__(self, allowed_schemes):
        self.allowed_schemes = allowed_schemes

    def __call__(self, *args, **kwargs):
        try:
            super(RedirectURIValidator, self).__call__(*args, **kwargs)
        except ValidationError as e:
            value = args[0]

            if value:
                if len(value.split('#')) > 1:
                    raise ValidationError('回调地址不支持锚点')

                scheme, netloc, path, query, fragment = urlsplit(value)
                if scheme.lower() not in self.allowed_schemes:
                    raise ValidationError('不支持的协议')
            else:
                raise ValidationError()


def validate_uris(value):
    v = RedirectURIValidator(allowed_schemes=["http", "https"])

    uris = value.split()
    if not uris:
        raise ValidationError("重定向地址不能为空")
    for uri in uris:
        v(uri)
