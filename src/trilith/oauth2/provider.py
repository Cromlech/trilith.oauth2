# coding: utf-8

import os
import uuid
import logging
import datetime

from functools import wraps

from oauthlib import oauth2
from oauthlib.oauth2 import RequestValidator, Server
from oauthlib.common import to_unicode

__all__ = ('OAuth2Provider', 'OAuth2RequestValidator')


log = logging.getLogger('myOAuthATM')


def uuid4_token(request):
    return str(uuid.uuid4())


def _get_uri_from_request(request):
    """
    The uri returned from request.uri is not properly urlencoded
    (sometimes it's partially urldecoded) This is a weird hack to get
    werkzeug to return the proper urlencoded string uri
    """
    uri = request.base_url
    if request.query_string:
        uri += '?' + request.query_string.decode('utf-8')
    return uri


def extract_params(request):
    headers = dict(request.headers)
    if 'wsgi.input' in headers:
        del headers['wsgi.input']
    if 'wsgi.errors' in headers:
        del headers['wsgi.errors']
    body = request.params.mixed()
    return request.url, request.method, body, headers


def validate():
    try:
        ret = server.validate_authorization_request(
            uri, http_method, body, headers
        )
        scopes, credentials = ret
        kwargs['scopes'] = scopes
        kwargs.update(credentials)
    except oauth2.FatalClientError as e:
        log.debug('Fatal client error %r', e)
        return redirect(e.in_uri(self.error_uri))
    except oauth2.OAuth2Error as e:
        log.debug('OAuth2Error: %r', e)
        return redirect(e.in_uri(redirect_uri))
    else:
        redirect_uri = request.values.get(
        'redirect_uri', self.error_uri
        )
 
    
    if not rv:
        # denied by user
        e = oauth2.AccessDeniedError()
        return redirect(e.in_uri(redirect_uri))
    return self.confirm_authorization_request()


class OAuthGatekeeper(object):

    def __init__(self, validator):
        self.validator = validator
        self.server = self.get_server(validator)
    
    def get_server(self, validator):
        return Server(
            validator,
            token_expires_in=100,
            token_generator=uuid4_token,
            refresh_token_generator=uuid4_token,
        )

    def verify_request(self, request, scopes):
        """Verify current request, get the oauth data.

        If you can't use the ``require_oauth`` decorator, you can fetch
        the data in your request body::

            def your_handler():
                valid, req = oauth.verify_request(['email'])
                if valid:
                    return jsonify(user=req.user)
                return jsonify(status='error')
        """
        uri, http_method, body, headers = extract_params(request)
        return self.server.verify_request(
            uri, http_method, body, headers, scopes
        )
        
    def error_uri(self):
        """The error page URI.

        When something turns error, it will redirect to this error page.
        You can configure the error page URI with Flask config::

            OAUTH2_PROVIDER_ERROR_URI = '/error'

        You can also define the error page by a named endpoint::

            OAUTH2_PROVIDER_ERROR_ENDPOINT = 'oauth.error'
        """
        error_uri = self.app.config.get('OAUTH2_PROVIDER_ERROR_URI')
        if error_uri:
            return error_uri
        error_endpoint = self.app.config.get('OAUTH2_PROVIDER_ERROR_ENDPOINT')
        if error_endpoint:
            return url_for(error_endpoint)
        return '/oauth/errors'

    def confirm_authorization_request(self):
        """When consumer confirm the authorization."""
        server = self.server
        scope = request.values.get('scope') or ''
        scopes = scope.split()
        credentials = dict(
            client_id=request.values.get('client_id'),
            redirect_uri=request.values.get('redirect_uri', None),
            response_type=request.values.get('response_type', None),
            state=request.values.get('state', None)
        )
        log.debug('Fetched credentials from request %r.', credentials)
        redirect_uri = credentials.get('redirect_uri')
        log.debug('Found redirect_uri %s.', redirect_uri)

        uri, http_method, body, headers = extract_params()
        try:
            ret = server.create_authorization_response(
                uri, http_method, body, headers, scopes, credentials)
            log.debug('Authorization successful.')
            return create_response(*ret)
        except oauth2.FatalClientError as e:
            log.debug('Fatal client error %r', e)
            return redirect(e.in_uri(self.error_uri))
        except oauth2.OAuth2Error as e:
            log.debug('OAuth2Error: %r', e)
            return redirect(e.in_uri(redirect_uri or self.error_uri))

    def token_handler(self, request):
        uri, http_method, body, headers = extract_params(request)
        credentials = {}
        ret = self.server.create_token_response(
            uri, http_method, body, headers, credentials
        )
        return ret


    def revoke_token(self):
        """Access/refresh token revoke.

        Any return value will get discarded as defined in [`RFC7009`_].

        You can control the access method but, as per [`RFC7009`_],
        it is recommended to only allow the `POST` method.

        .. _`RFC7009`: http://tools.ietf.org/html/rfc7009
        """
        token = request.values.get('token')
        request.token_type_hint = request.values.get('token_type_hint')
        if token:
            request.token = token

        uri, http_method, body, headers = extract_params()
        ret = server.create_revocation_response(
            uri, headers=headers, body=body, http_method=http_method)
        return create_response(*ret)

    def require_oauth(self, *scopes):
        """Protect resource with specified scopes."""
        before_request_funcs = []  # use subscription
        after_request_funcs = []  # use subscription
        
        for func in before_request_funcs:
            func()

        if hasattr(request, 'oauth') and request.oauth:
            return f(*args, **kwargs)

        valid, req = self.verify_request(scopes)
        for func in after_request_funcs:
            valid, req = func(valid, req)
            if not valid:
                return abort(401)
        request.oauth = req
        return
