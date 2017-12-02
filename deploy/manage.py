#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @File  : manage.py
# @Author: Pen
# @Date  : 2017-11-22 16:14
# @Desc  :

import os
import oauth_pen.provider as op
import Pen_Auth.constants as oc

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "Pen_Test.settings")


def create_application():
    """
    创建一个应用程序
    :return:
    """

    app = {
        'client_type': oc.APPLICATION_CLIENT_TYPE[0],
        'authorization_grant_type': oc.APPLICATION_GRANT_TYPE[0],
        'name': 'Grant 密码',
        'redirect_uris': ''
    }

    op.add_application(**app)
