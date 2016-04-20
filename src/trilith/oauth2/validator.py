# -*- coding: utf-8 -*-

import os
import logging
from datetime import datetime, timedelta
from functools import wraps
from oauthlib import oauth2
from oauthlib.oauth2 import RequestValidator
from oauthlib.common import to_unicode


logger = logging.getLogger('trilith.oauth2')


class OAuth2RequestValidator(RequestValidator):
    """Subclass of Request Validator.

    :param clientgetter: a function to get client object
    :param tokengetter: a function to get bearer token
    :param tokensetter: a function to save bearer token
    :param grantgetter: a function to get grant token
    :param grantsetter: a function to save grant token
    """
    def __init__(self, users, clients, tokens, grants):
        self._users = users
        self._clients = clients
        self._tokens = tokens
        self._grants = grants
        
    def client_authentication_required(self, request, *args, **kwargs):
        """Determine if client authentication is required for current request.

        According to the rfc6749, client authentication is required in the
        following cases:

        Resource Owner Password Credentials Grant: see `Section 4.3.2`_.
        Authorization Code Grant: see `Section 4.1.3`_.
        Refresh Token Grant: see `Section 6`_.

        .. _`Section 4.3.2`: http://tools.ietf.org/html/rfc6749#section-4.3.2
        .. _`Section 4.1.3`: http://tools.ietf.org/html/rfc6749#section-4.1.3
        .. _`Section 6`: http://tools.ietf.org/html/rfc6749#section-6
        """
        if request.grant_type == 'password':
            client = self._clients.get(request.client_id)
            return client is None or client.client_type == 'confidential' \
                or client.client_secret
        elif request.grant_type == 'authorization_code':
            client = self._clients.get(request.client_id)
            return client is None or client.client_type == 'confidential'
        return 'Authorization' in request.headers \
                and request.grant_type == 'refresh_token'

    def authenticate_client(self, request, *args, **kwargs):
        """Authenticate itself in other means.

        Other means means is described in `Section 3.2.1`_.

        .. _`Section 3.2.1`: http://tools.ietf.org/html/rfc6749#section-3.2.1
        """
        auth = request.headers.get('Authorization', None)
        logger.debug('Authenticate client %r', auth)
        if auth:
            try:
                _, s = auth.split(' ')
                client_id, client_secret = decode_base64(s).split(':')
                client_id = to_unicode(client_id, 'utf-8')
                client_secret = to_unicode(client_secret, 'utf-8')
            except Exception as e:
                logger.debug('Authenticate client failed with exception: %r', e)
                return False
        else:
            client_id = request.client_id
            client_secret = request.client_secret

        client = self._clients.find(id=client_id, secret=client_secret)
        if client is None:
            logger.debug('Authenticate client failed, '
                         'client not found or secret not match.')
            return False

        request.client = client
        logger.debug('Authenticate client success.')
        return True

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        """Authenticate a non-confidential client.

        :param client_id: Client ID of the non-confidential client
        :param request: The Request object passed by oauthlib
        """
        logger.debug('Authenticate client %r.', client_id)
        client = self._clients.get(client_id)
        if client is None:
            logger.debug('Authenticate failed, client not found.')
            return False

        # attach client on request for convenience
        request.client = client
        return True

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client,
                             *args, **kwargs):
        """Ensure client is authorized to redirect to the redirect_uri.

        This method is used in the authorization code grant flow. It will
        compare redirect_uri and the one in grant token strictly, you can
        add a `validate_redirect_uri` function on grant for a customized
        validation.
        """
        client = client or self._clients[client_id]
        logger.debug('Confirm redirect uri for client %r and code %r.',
                  client.client_id, code)
        grant = self._grants.find(id=client.id, code=code)
        if not grant:
            logger.debug('Grant not found.')
            return False
        if hasattr(grant, 'validate_redirect_uri'):
            return grant.validate_redirect_uri(redirect_uri)
        logger.debug('Compare redirect uri for grant %r and %r.',
                  grant.redirect_uri, redirect_uri)

        testing = 'OAUTHLIB_INSECURE_TRANSPORT' in os.environ
        if testing and redirect_uri is None:
            # For testing
            return True

        return grant.redirect_uri == redirect_uri

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        """Get the list of scopes associated with the refresh token.

        This method is used in the refresh token grant flow.  We return
        the scope of the token to be refreshed so it can be applied to the
        new access token.
        """
        logger.debug('Obtaining scope of refreshed token.')
        tok = self._tokens.find(refresh_token=refresh_token)
        return tok.scopes

    def confirm_scopes(self, refresh_token, scopes, request, *args, **kwargs):
        """Ensures the requested scope matches the scope originally granted
        by the resource owner. If the scope is omitted it is treated as equal
        to the scope originally granted by the resource owner.

        DEPRECATION NOTE: This method will cease to be used in oauthlib>0.4.2,
        future versions of ``oauthlib`` use the validator method
        ``get_original_scopes`` to determine the scope of the refreshed token.
        """
        if not scopes:
            logger.debug('Scope omitted for refresh token %r', refresh_token)
            return True
        logger.debug('Confirm scopes %r for refresh token %r',
                  scopes, refresh_token)
        tok = self._tokens.find(refresh_token=refresh_token)
        return tok.scopes == scopes

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        """Default redirect_uri for the given client."""
        request.client = request.client or self._clients[client_id]
        redirect_uri = request.client.default_redirect_uri
        logger.debug('Found default redirect uri %r', redirect_uri)
        return redirect_uri

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        """Default scopes for the given client."""
        request.client = request.client or self._clients[client_id]
        scopes = request.client.default_scopes
        logger.debug('Found default scopes %r', scopes)
        return scopes

    def invalidate_authorization_code(self, client_id, code, request,
                                      *args, **kwargs):
        """Invalidate an authorization code after use.

        We keep the temporary code in a grant, which has a `delete`
        function to destroy itself.
        """
        logger.debug('Destroy grant token for client %r, %r', client_id, code)
        grant = self._grants.find(id=client_id, code=code)
        self._grant.delete(grant)

    def save_authorization_code(self, client_id, code, request,
                                *args, **kwargs):
        """Persist the authorization code."""
        logger.debug(
            'Persist authorization code %r for client %r',
            code, client_id
        )
        import pdb; pdb.set_trace()
        request.client = request.client or self._clients[client_id]
        self._grant.add(client_id, code, request, *args, **kwargs)
        return request.client.default_redirect_uri

    def save_bearer_token(self, token, request, *args, **kwargs):
        """Persist the Bearer token."""
        logger.debug('Save bearer token %r', token)
        data = {}
        if request.user is not None:
            data['user_id'] = request.user.id
        if request.client_id is not None:
            data['client_id'] = request.client_id

        # Cooking the expiration time
        expires_in = token.pop('expires_in')
        expires = datetime.utcnow() + timedelta(seconds=expires_in)
        data['expires'] = expires

        # Pushing the rest of the token data
        data.update(token)

        self._tokens.add(**data)
        return request.client.default_redirect_uri

    def validate_bearer_token(self, token, scopes, request):
        """Validate access token.

        :param token: A string of random characters
        :param scopes: A list of scopes
        :param request: The Request object passed by oauthlib

        The validation validates:

            1) if the token is available
            2) if the token has expired
            3) if the scopes are available
        """        
        logger.debug('Validate bearer token %r', token)
        tok = self._tokens.find(access_token=token)
        if tok is None:
            msg = 'Bearer token not found.'
            request.error_message = msg
            logger.debug(msg)
            return False

        # validate expires
        if datetime.utcnow() > tok.expires:
            msg = 'Bearer token is expired.'
            request.error_message = msg
            logger.debug(msg)
            return False

        # validate scopes
        if scopes and not set(tok.scopes) & set(scopes):
            msg = 'Bearer token scope not valid.'
            request.error_message = msg
            logger.debug(msg)
            return False

        request.access_token = tok
        request.scopes = scopes

        if hasattr(tok, 'client'):
            request.client = tok.client
        elif hasattr(tok, 'client_id'):
            request.client = self._clients[tok.client_id]
        return True

    def validate_client_id(self, client_id, request, *args, **kwargs):
        """Ensure client_id belong to a valid and active client."""
        logger.debug('Validate client %r', client_id)
        client = request.client or self._clients[client_id]
        if client:
            # attach client to request object
            request.client = client
            return True
        return False

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        """Ensure the grant code is valid."""
        client = client or self._clients[client_id]
        logger.debug(
            'Validate code for client %r and code %r', client.client_id, code
        )
        grant = self._grant.find(id=client.client_id, code=code)
        if grant is None:
            logger.debug('Grant not found.')
            return False
        if hasattr(grant, 'expires') and \
           datetime.datetime.utcnow() > grant.expires:
            logger.debug('Grant is expired.')
            return False

        request.state = kwargs.get('state')
        request.user = grant.user
        request.scopes = grant.scopes
        return True

    def validate_grant_type(self, client_id, grant_type, client, request,
                            *args, **kwargs):
        """Ensure the client is authorized to use the grant type requested.

        It will allow any of the four grant types (`authorization_code`,
        `password`, `client_credentials`, `refresh_token`) by default.
        Implemented `allowed_grant_types` for client object to authorize
        the request.

        It is suggested that `allowed_grant_types` should contain at least
        `authorization_code` and `refresh_token`.
        """
        default_grant_types = (
            'authorization_code', 'password',
            'client_credentials', 'refresh_token',
        )
        
        # Grant type is allowed if it is part of the 'allowed_grant_types'
        # of the selected client or if it is one of the default grant types
        if hasattr(client, 'allowed_grant_types'):
            if grant_type not in client.allowed_grant_types:
                return False
        else:
            if grant_type not in default_grant_types:
                return False

        return True

    def validate_redirect_uri(self, client_id, redirect_uri, request,
                              *args, **kwargs):
        """Ensure client is authorized to redirect to the redirect_uri.

        This method is used in the authorization code grant flow and also
        in implicit grant flow. It will detect if redirect_uri in client's
        redirect_uris strictly, you can add a `validate_redirect_uri`
        function on grant for a customized validation.
        """
        request.client = request.client or self._clients[client_id]
        client = request.client
        if hasattr(client, 'validate_redirect_uri'):
            return client.validate_redirect_uri(redirect_uri)
        return redirect_uri in client.redirect_uris

    def validate_refresh_token(self, refresh_token, client, request,
                               *args, **kwargs):
        """Ensure the token is valid and belongs to the client

        This method is used by the authorization code grant indirectly by
        issuing refresh tokens, resource owner password credentials grant
        (also indirectly) and the refresh token grant.
        """

        token = self._tokens.find(refresh_token=refresh_token)

        if token and token.client_id == client.client_id:
            # Make sure the request object contains user and client_id
            request.client_id = token.client_id
            request.user = token.user
            return True
        return False

    def validate_response_type(self, client_id, response_type, client, request,
                               *args, **kwargs):
        """Ensure client is authorized to use the response type requested.

        It will allow any of the two (`code`, `token`) response types by
        default. Implemented `allowed_response_types` for client object
        to authorize the request.
        """
        if response_type not in ('code', 'token'):
            return False

        if hasattr(client, 'allowed_response_types'):
            return response_type in client.allowed_response_types
        return True

    def validate_scopes(self, client_id, scopes, client, request,
                        *args, **kwargs):
        """Ensure the client is authorized access to requested scopes."""
        if hasattr(client, 'validate_scopes'):
            return client.validate_scopes(scopes)
        return set(client.default_scopes).issuperset(set(scopes))

    def validate_user(self, username, password, client, request,
                      *args, **kwargs):
        """Ensure the username and password is valid.

        Attach user object on request for later using.
        """
        logger.debug('Validating username %r and its password', username)
        try:
            user = self._users.find(
                id=username, password=password, client_id=client)
            if user is not None:
                request.user = user
                return True
            return False
        except NotImplementedError:
            logger.debug('Password credential authorization is disabled.')
            return False

    def revoke_token(self, token, token_type_hint, request, *args, **kwargs):
        """Revoke an access or refresh token.
        """
        if token_type_hint:
            tok = self._tokens.find(**{token_type_hint: token})
        else:
            tok = self._tokens.find(access_token=token)
            if tok is None:
                tok = self._tokens.find(refresh_token=token)

        if tok is not None:
            client = self._clients.get(request.client_id)
            if client is not None and client.client_id == tok.client_id:
                request.client_id = tok.client_id
                request.user = tok.user
                self._tokens.delete(tok)
                return True

        msg = 'Invalid token supplied.'
        logger.debug(msg)
        request.error_message = msg
        return False
