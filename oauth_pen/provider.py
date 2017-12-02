#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @File  : provider.py
# @Author: Pen
# @Date  : 2017-11-22 16:19
# @Desc  :

import oauth_pen.models as om


# application

def add_application(**kwargs):
    return om.Application.objects.create(**kwargs)


# token

def add_token(**kwargs):
    """
    创建token
    :param kwargs:
    :return:
    """
    om.AccessToken.objects.create(**kwargs)
