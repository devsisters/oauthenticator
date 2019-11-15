import os
import logging
import json
import base64

import jwt
import urllib

from traitlets import Unicode, Dict, Bool

from tornado.auth import OAuth2Mixin
from tornado.httpclient import HTTPRequest, AsyncHTTPClient, HTTPError

from jupyterhub.auth import LocalAuthenticator
from .oauth2 import OAuthLoginHandler, OAuthenticator


class DevsistersAuthMixin(OAuth2Mixin):
    _OAUTH_AUTHORIZE_URL = os.environ.get("OAUTH2_AUTHORIZE_URL")
    _OAUTH_TOKEN_URL = os.environ.get("OAUTH2_TOKEN_URL")


class DevsistersLoginHandler(OAuthLoginHandler, DevsistersAuthMixin):
    pass


class DevsistersOAuthenticator(OAuthenticator):
    logger = logging.getLogger(__name__)

    login_service = "keycloak"

    login_handler = DevsistersLoginHandler

    token_url = Unicode(
        os.environ.get('OAUTH2_TOKEN_URL', ''),
        config=True,
        help="Access token endpoint URL"
    )
    extra_params = Dict(
        help="Extra parameters for first POST request"
    ).tag(config=True)

    tls_verify = Bool(
        os.environ.get('OAUTH2_TLS_VERIFY', 'True').lower() in {'true', '1'},
        config=True,
        help="Disable TLS verification on http request"
    )

    basic_auth = Bool(
        os.environ.get('OAUTH2_BASIC_AUTH', 'True').lower() in {'true', '1'},
        config=True,
        help="Disable basic authentication for access token request"
    )

    def _get_user(self, resp):
        try:
            token = resp['access_token']
            auth_data = jwt.decode(token, verify=True, options={'verify_signature': False},
                                   audience=self.client_id)

            # XXX(kimtkyeom): Pod등을 생성할 때 name을 활용하는데, email의 id (@devsisters.. 를 제외한)
            # 부분을 사용하는 것이 id 표시 가독성 등의 측면에서 가장 효율적인 듯 하여, '@'를 기준으로 split
            name = auth_data['email'].split("@")[0]

            groups = auth_data['resource_access'][self.client_id]['roles']

            auth_state = dict(
                access_token=resp['access_token'],
                refresh_token=resp.get('refresh_token', None),
                token_type=resp['token_type'],
                scope=resp.get('scope', ''),
                oauth_user=resp
            )

            return dict(
                name=name,
                groups=groups,
                auth_state=auth_state
            )

        except (ValueError, KeyError) as e:
            self.logger.warning("get_oauth_user_info has failed to decode token: \n{}".format(e))

    async def authenticate(self, handler, data=None):
        self.logger.info("Start auth: {}, {}".format(handler, data))

        code = handler.get_argument("code")
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()

        params = dict(
            redirect_uri=self.get_callback_url(handler),
            code=code,
            grant_type='authorization_code'
        )
        params.update(self.extra_params)

        if self.token_url:
            url = self.token_url
        else:
            raise ValueError("Please set the OAUTH2_TOKEN_URL environment variable")

        headers = {
            "Accept": "application/x-www-form-urlencoded",
            "User-Agent": "JupyterHub"
        }

        if self.basic_auth:
            b64key = base64.b64encode(
                bytes(
                    "{}:{}".format(self.client_id, self.client_secret),
                    "utf8"
                )
            )
            headers.update({"Authorization": "Basic {}".format(b64key.decode("utf8"))})

        req = HTTPRequest(url,
                          method="POST",
                          headers=headers,
                          validate_cert=self.tls_verify,
                          body=urllib.parse.urlencode(params)  # Body is required for a POST...
                          )

        resp = await http_client.fetch(req)

        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        return self._get_user(resp_json)


class LocalDevsistersOAuthenticator(LocalAuthenticator, DevsistersOAuthenticator):
    pass
