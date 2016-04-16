# -*- coding: utf-8 -*-


class IClientGetter(Interface):
    """Register a function as the client getter.
    
    The function accepts one parameter `client_id`, and it returns
    a client object with at least these information:

      - client_id: A random string
      - client_secret: A random string
      - client_type: A string represents if it is `confidential`
      - redirect_uris: A list of redirect uris
      - default_redirect_uri: One of the redirect uris
      - default_scopes: Default scopes of the client

    The client may contain more information, which is suggested:

      - allowed_grant_types: A list of grant types
      - allowed_response_types: A list of response types
      - validate_scopes: A function to validate scopes
    """
    def __call__(client_id):
        pass
    


class IUserGetter(Interface):
    """Register a function as the user getter.

    This decorator is only required for **password credential**
    authorization::

    parameter `request` is an OAuthlib Request object.
    Maybe you will need it somewhere
    """
    def __call__(username, password, client, request, *args, **kwargs):
       pass


class ITokenGetter(Interface):
    """Register a function as the token getter.

    The function accepts an `access_token` or `refresh_token` parameters,
    and it returns a token object with at least these information:
    
    - access_token: A string token
    - refresh_token: A string token
    - client_id: ID of the client
    - scopes: A list of scopes
    - expires: A `datetime.datetime` object
    - user: The user object

    The implementation of tokengetter should accepts two parameters,
    one is access_token the other is refresh_token::

    @oauth.tokengetter
    def bearer_token(access_token=None, refresh_token=None):
    if access_token:
    return get_token(access_token=access_token)
    if refresh_token:
    return get_token(refresh_token=refresh_token)
    return None
    """

    
class ITokenSetter(Interface):
    """Register a function to save the bearer token.

    The setter accepts two parameters at least, one is token,
    the other is request::
    
    @oauth.tokensetter
    def set_token(token, request, *args, **kwargs):
    save_token(token, request.client, request.user)
    
    The parameter token is a dict, that looks like::
    
    {
    u'access_token': u'6JwgO77PApxsFCU8Quz0pnL9s23016',
    u'token_type': u'Bearer',
    u'expires_in': 3600,
    u'scope': u'email address'
    }
    
    The request is an object, that contains an user object and a
    client object.
    """


class GrantGetter(Interface):
    """Register a function as the grant getter.
    
    The function accepts `client_id`, `code` and more::

    @oauth.grantgetter
    def grant(client_id, code):
    return get_grant(client_id, code)
    
    It returns a grant object with at least these information:
    
    - delete: A function to delete itself
    """


class GrantSetter(Interface):
    """Register a function to save the grant code.

    The function accepts `client_id`, `code`, `request` and more::
    
    @oauth.grantsetter
    def set_grant(client_id, code, request, *args, **kwargs):
    save_grant(client_id, code, request.user, request.scopes)
    """
