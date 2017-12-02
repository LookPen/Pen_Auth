#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @File  : exceptions.py
# @Author: Pen
# @Date  : 2017-11-23 15:09
# @Desc  :


class OAuthError(Exception):
    def __init__(self, error=None, redirect_uri=None, *args, **kwargs):
        super(OAuthError, self).__init__(*args, **kwargs)
        self.oauth_error = error

        if redirect_uri:
            self.oauth_error.redirect_uri = redirect_uri


class FatalClientError(OAuthError):
    pass
