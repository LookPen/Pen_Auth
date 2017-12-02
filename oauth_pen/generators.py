#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @File  : generators.py
# @Author: Pen
# @Date  : 2017-11-22 11:33
# @Desc  : 生成器

from oauthlib.common import generate_client_id, CLIENT_ID_CHARACTER_SET, UNICODE_ASCII_CHARACTER_SET, generate_token


class ClientIdGenerator:
    def hash(self):
        """
        生成一个客户端ID(只包含数字/小写/大写)
        :return:
        """
        return generate_client_id(length=40, chars=CLIENT_ID_CHARACTER_SET)


class ClientSecretGenerator:
    def hash(self):
        """
        生成一个客户端密钥
        :return:
        """
        return generate_token(length=128, chars=UNICODE_ASCII_CHARACTER_SET)


def generate_client_id():
    """
    产生客户端ID 的工厂,后期加在setting 中配置ClientIdGenerator TODO
    :return:
    """

    # client_id_generator = oauth2_settings.CLIENT_ID_GENERATOR_CLASS()

    client_id_generator = ClientIdGenerator()
    return client_id_generator.hash()


def generate_client_secret():
    """
        产生客户端密钥的工厂
        :return:
        """
    client_secret_generator = ClientIdGenerator()
    return client_secret_generator.hash()
