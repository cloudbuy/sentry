"""
GitLab OAuth support.

This contribution adds support for GitHub OAuth service. The settings
GITLAB_APP_ID and GITLAB_API_SECRET must be defined with the values
given by GitHub application registration process.

Extended permissions are supported by defining GITHUB_EXTENDED_PERMISSIONS
setting, it must be a list of values to request.

By default account id and token expiration time are stored in extra_data
field, check OAuthBackend class for details on how to extend it.
"""
from __future__ import absolute_import

import simplejson

from django.conf import settings
from six.moves.urllib.error import HTTPError
from six.moves.urllib.parse import urlencode
from social_auth.utils import dsa_urlopen
from social_auth.backends import BaseOAuth2, OAuthBackend
from social_auth.exceptions import AuthFailed


# GitLab configuration
GITLAB_BASE_DOMAIN = getattr(settings, 'GITLAB_BASE_DOMAIN', None)
GITLAB_SCHEME = getattr(settings, 'GITLAB_HTTP_SCHEME', 'https')
GITLAB_API_VERSION = getattr(settings, 'GITLAB_API_VERSION', 4)
GITLAB_SCOPE = getattr(settings, 'GITLAB_AUTH_SCOPE', 'api')

GITLAB_ACCESS_TOKEN_URL = '{0}://{1}/oauth/token'.format(SCHEME, BASE_DOMAIN)
GITLAB_AUTHORIZE_URL = '{0}://{1}/oauth/authorize'.format(SCHEME, BASE_DOMAIN)
GITLAB_API_BASE_URL = '{0}://{1}/api/v{2}'.format(SCHEME, BASE_DOMAIN, API_VERSION)


class GitlabBackend(OAuthBackend):
    """GitLab OAuth authentication backend"""
    name = 'gitlab'


class GitlabAuth(BaseOAuth2):
    """GitLab OAuth2 mechanism"""
    AUTHORIZATION_URL = GITLAB_AUTHORIZATION_URL
    ACCESS_TOKEN_URL = GITLAB_ACCESS_TOKEN_URL
    AUTH_BACKEND = GitlabBackend
    SETTINGS_KEY_NAME = 'GITLAB_APP_ID'
    SETTINGS_SECRET_NAME = 'GITLAB_API_SECRET'
    DEFAULT_SCOPE = [GITLAB_SCOPE]


# Backend definition
BACKENDS = {
    'gitlab': GitlabAuth,
}
