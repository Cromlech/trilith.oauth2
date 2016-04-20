# -*- coding: utf-8 -*-

from zope.interface import Interface
from zope.schema import ValidationError
from zope.schema import (
    Datetime, Int, ASCIILine, TextLine, Text, Choice, List, Set)


class InvalidSizeError(ValidationError):
    __doc__ = u'Please respect the specified field size.'


def sized(max):
    def size_constraint(value):
        if len(value) <= max:
            return True
        raise InvalidSizeError
    return size_constraint


class IUser(Interface):

    username = ASCIILine(
        title=u'Unique identifier',
        constraint=sized(128),
        required=True)

    common_name = TextLine(
        title=u'Full name',
        constraint=sized(128),
        required=True)

    function = TextLine(
        title=u'Job function or title',
        constraint=sized(128),
        required=True)


class IClient(Interface):
    
    id = ASCIILine(
        title=u'Unique identifier',
        constraint=sized(40),
        required=True)

    name = TextLine(
        title=u'Name',
        constraint=sized(40),
        required=True)

    type = Choice(
        title=u'Client type',
        values=('public', 'confidential'),
        default='public',
        required=True)

    secret = ASCIILine(
        title=u'Secret',
        constraint=sized(55),
        required=True)

    user_id = ASCIILine(
        title=u'Linked user',
        constraint=sized(128),
        required=False)

    redirect_uris = List(
        title=u"Redirection URIs",
        value_type=ASCIILine(constraint=sized(255)),
        required=True)

    default_scopes = Set(
        title=u"Allowed scopes",
        value_type=ASCIILine(),
        required=True)


class IToken(Interface):

    type = Choice(
        title=u'Token type',
        values=('Bearer', 'MAC'),
        default='Bearer',
        required=True)

    access_token = ASCIILine(
        title=u'Access token',
        constraint=sized(255),
        required=True)
        
    refresh_token = ASCIILine(
        title=u'Refresh token',
        constraint=sized(255),
        required=True)

    client_id = ASCIILine(
        title=u'Client',
        constraint=sized(40),
        required=True)
        
    user_id = ASCIILine(
        title=u'User',
        constraint=sized(128),
        required=False)

    expires = Datetime(
        title=u'Expiration date',
        required=True)
        
    scopes = Set(
        title=u"Allowed scopes",
        value_type=ASCIILine(),
        required=True)

        
class IGrant(Interface):

    client_id = ASCIILine(
        title=u'Client',
        constraint=sized(40),
        required=True)

    user_id = ASCIILine(
        title=u'User',
        constraint=sized(128),
        required=False)
        
    redirect_uri = ASCIILine(
        title=u"Redirection URIs",
        constraint=sized(255),
        required=True)

    code = ASCIILine(
        title=u'Code',
        constraint=sized(255),
        required=True)

    expires = Datetime(
        title=u'Expiration date',
        required=True)
        
    scopes = Set(
        title=u"Allowed scopes",
        value_type=ASCIILine(),
        required=False)
        

class IStorage(Interface):

    def __getitem__(uid):
        pass

    def get(*args, **kwargs):
        pass

    def set(item):
        pass

    def __iter__():
        pass

    def __contains__(key):
        pass

    def find(**kwargs):
        pass


class IUsers(IStorage):
    pass


class IGrants(IStorage):
    pass


class IClients(IStorage):
    pass


class ITokens(IStorage):
    pass
