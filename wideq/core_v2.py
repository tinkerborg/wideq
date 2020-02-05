"""A low-level, general abstraction for the LG SmartThinQ API.
"""
import base64
import uuid
from urllib.parse import urljoin, urlencode, urlparse, parse_qs, quote
import hashlib
import hmac
import datetime
import requests
import ssl

from tempfile import NamedTemporaryFile
from OpenSSL.SSL import FILETYPE_PEM
from OpenSSL import crypto

import paho.mqtt.client as mqtt

from .core_exceptions import *
from . import core

#v2
API_KEY = 'VGhpblEyLjAgU0VSVklDRQ=='
CLIENT_ID = '65260af7e8e6547b51fdccf930097c51eb9885a508d3fddfa9ee6cdec22ae1bd'
MESSAGE_ID = 'wideq'
SVC_PHASE = 'OP'
APP_LEVEL = 'PRD'
APP_OS = 'LINUX'
APP_TYPE = 'NUTS'
APP_VER = '3.0.1700'
DATA_ROOT = 'result'
SECURITY_KEY = 'nuts_securitykey'
SVC_CODE = 'SVC202'
CLIENT_ID = 'LGAO221A02'
OAUTH_SECRET_KEY = 'c053c2a6ddeb7ad97cb0eed0dcb31cf8'
DATE_FORMAT = '%a, %d %b %Y %H:%M:%S +0000'

GATEWAY_URL = 'https://route.lgthinq.com:46030/v1/service/application/gateway-uri'
OAUTH_REDIRECT_URI = 'https://kr.m.lgaccount.com/login/iabClose'

AWS_IOTT_CA_CERT_URL = 'https://www.symantec.com/content/en/us/enterprise/verisign/roots/VeriSign-Class%203-Public-Primary-Certification-Authority-G5.pem'
AWS_IOTT_ALPN_PROTOCOL = "x-amzn-mqtt-ca"


def gen_uuid():
    return str(uuid.uuid4())

def oauth2_signature(message, secret):
    """Get the base64-encoded SHA-1 HMAC digest of a string, as used in
    OAauth2 request signatures.

    Both the `secret` and `message` are given as text strings. We use
    their UTF-8 equivalents.
    """

    secret_bytes = secret.encode('utf8')
    hashed = hmac.new(secret_bytes, message.encode('utf8'), hashlib.sha1)
    digest = hashed.digest()
    return base64.b64encode(digest)

def get_list(obj, key):
    """Look up a list using a key from an object.

    If `obj[key]` is a list, return it unchanged. If is something else,
    return a single-element list containing it. If the key does not
    exist, return an empty list.
    """
    try:
        val = obj[key]
    except KeyError:
        return []

    if isinstance(val, list):
        return val
    else:
        return [val]

def thinq2_headers(extra_headers={}, access_token=None, user_number=None, country="US", language="en-US"):

    headers = {
        'Accept': 'application/json',
        'Content-type': 'application/json;charset=UTF-8',
        'x-api-key': API_KEY,
        'x-client-id': CLIENT_ID,
        'x-country-code': country,
        'x-language-code': language,
        'x-message-id': MESSAGE_ID,
        'x-service-code': SVC_CODE,
        'x-service-phase': SVC_PHASE,
        'x-thinq-app-level': APP_LEVEL,
        'x-thinq-app-os': APP_OS,
        'x-thinq-app-type': APP_TYPE,
        'x-thinq-app-ver': APP_VER,
        'x-thinq-security-key': SECURITY_KEY,
    }

    if access_token:
        headers['x-emp-token'] = access_token

    if user_number:
        headers['x-user-no'] = user_number

    return { **headers, **extra_headers }

def thinq2_get(url, access_token=None, user_number=None, headers={}, country="US", language="en-US"):

    res = requests.get(url, headers=thinq2_headers(
        access_token=access_token, user_number=user_number, extra_headers=headers, country=country, language=language))

    out = res.json()

    if 'resultCode' in out:
        code = out['resultCode']
        if code != '0000':
            if code == "0102":
                raise NotLoggedInError()
            elif code == "0106":
                raise NotConnectedError()
            else:
                raise APIError(code, "error")

    return out['result']

def thinq2_post(url, data=None, access_token=None, user_number=None, headers={}, country="US", language="en-US"):
    headers = thinq2_headers(
        access_token=access_token, user_number=user_number, extra_headers=headers, country=country, language=language)
    res = requests.post(url, json=data, headers=thinq2_headers(
        access_token=access_token, user_number=user_number, extra_headers=headers, country=country, language=language))

    out = res.json()

    if 'resultCode' in out:
        code = out['resultCode']
        if code != '0000':
            if code == "0102":
                raise NotLoggedInError()
            elif code == "0106":
                raise NotConnectedError()
            else:
                raise APIError(code, "error")

    return out['result']


def gateway_info(country, language):
    """ TODO
    """
    return thinq2_get(GATEWAY_URL, country=country, language=language)

def parse_oauth_callback(url):
    """Parse the URL to which an OAuth login redirected to obtain two
    tokens: an access token for API credentials, and a refresh token for
    getting updated access tokens.
    """

    params = parse_qs(urlparse(url).query)
    return params['oauth2_backend_url'][0], params['code'][0], params['user_number'][0]

def auth_request(oauth_url, data):
    """Use an auth code to log into the v2 API and obtain an access token
    and refresh token.
    """
    auth_path = '/oauth/1.0/oauth2/token'
    url = urljoin(oauth_url, '/oauth/1.0/oauth2/token')
    timestamp = datetime.datetime.utcnow().strftime(DATE_FORMAT)
    req_url = '{}?{}'.format(auth_path, urlencode(data))
    sig = oauth2_signature('{}\n{}'.format(req_url, timestamp), OAUTH_SECRET_KEY)

    headers = {
        'x-lge-appkey': CLIENT_ID,
        'x-lge-oauth-signature': sig,
        'x-lge-oauth-date': timestamp,
        'Accept': 'application/json'
    }

    res = requests.post(url, headers=headers, data=data)

    if res.status_code != 200:
        raise TokenError()

    return res.json()

def login(oauth_url, auth_code):
    """Get a new access_token using an authorization_code

    May raise a `tokenError`.
    """

    out = auth_request(oauth_url, {
        'code': auth_code,
        'grant_type': 'authorization_code',
        'redirect_uri': OAUTH_REDIRECT_URI
    })

    return out['access_token'], out['refresh_token']

def refresh_auth(oauth_root, refresh_token):
    """Get a new access_token using a refresh_token.

    May raise a `TokenError`.
    """
    out = auth_request(oauth_root, {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token
    })

    return out['access_token']

class Gateway(core.Gateway):
    @classmethod
    def discover(cls, country, language):
        gw = gateway_info(country, language)
        return cls(gw['empUri'], gw['thinq2Uri'], gw['empUri'],
                   country, language)

    def oauth_url(self):
        """Construct the URL for users to log in (in a browser) to start an
        authenticated session.
        """

        url = urljoin(self.auth_base, 'spx/login/signIn')
        query = urlencode({
            'country': self.country,
            'language': self.language,
            'svc_list': SVC_CODE,
            'client_id': CLIENT_ID,
            'division': 'ha',
            'redirect_uri': OAUTH_REDIRECT_URI,
            'state': uuid.uuid1().hex,
            'show_thirdparty_login': 'GGL,AMZ,FBK'
        })
        return '{}?{}'.format(url, query)

    def dump(self):
        return {
            'auth_base': self.auth_base,
            'api_root': self.api_root,
            'oauth_root': self.oauth_root,
            'country': self.country,
            'language': self.language,
        }

class Auth(object):
    def __init__(self, gateway, oauth_url, access_token, refresh_token, user_number):
        self.gateway = gateway
        self.oauth_url = oauth_url
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.user_number = user_number

    @classmethod
    def from_url(cls, gateway, url):
        """Create an authentication using an OAuth callback URL.
        """
        oauth_url, auth_code, user_number = parse_oauth_callback(url)
        access_token, refresh_token = login(oauth_url, auth_code)

        return cls(gateway, oauth_url, access_token, refresh_token, user_number)

    def start_session(self, api_version=1):
        """Start an API session for the logged-in user. Return the
        Session object and a list of the user's devices.
        """
        #access_token, refresh_token = login(self.oauth_url, self.auth_code,
        #                     self.gateway.country, self.gateway.language)
        #session_id = session_info['jsessionId']
        return Session(self), []
        #return Session(self, session_id), get_list(session_info, 'item')

    def refresh(self):
        """Refresh the authentication, returning a new Auth object.
        """

        new_access_token = refresh_auth(self.oauth_url,
                                        self.refresh_token)
        return Auth(self.gateway, self.oauth_url, new_access_token, self.refresh_token, self.user_number)

    def dump(self):
        return {
            'access_token': self.access_token,
            'refresh_token': self.refresh_token,
            'oauth_url': self.oauth_url,
            'user_number': self.user_number,
        }

    @classmethod
    def load(cls, gateway, data):
      return cls(gateway, **data)

class Session(object):
    def __init__(self, auth, session_id=None):
        self.auth = auth
        self.session_id = session_id
        self._monitor = None

    def post(self, path, data=None):
        """Make a POST request to the API server.

        This is like `lgedm_post`, but it pulls the context for the
        request from an active Session.
        """
        url = urljoin(self.auth.gateway.api_root + '/', path)
        return thinq2_post(url, data, self.auth.access_token, self.auth.user_number, country=self.auth.gateway.country, language=self.auth.gateway.language)

    def get(self, path):
        url = urljoin(self.auth.gateway.api_root + '/', path)
        return thinq2_get(url, self.auth.access_token, self.auth.user_number, country=self.auth.gateway.country, language=self.auth.gateway.language)

    def get_devices(self):
        """Get a list of devices associated with the user's account.

        Return a list of dicts with information about the devices.
        """
        return get_list(self.get('service/application/dashboard'), 'item')

    @property
    def monitor(self):
        if self._monitor is None:
            self._monitor = AWSMQTTMonitor.from_session(self)
        return self._monitor

    @property
    def mqtt_endpoint(self):
        res = thinq2_get("https://common.lgthinq.com/route",
            country=self.auth.gateway.country,
            language=self.auth.gateway.language)
        if 'mqttServer' in res:
            return res['mqttServer']
        # TODO - exception handling
        return None


    def monitor_start(self, device_id):
        self.monitor.subscribe(device_id)
        """Begin monitoring a device's status.

        Return a "work ID" that can be used to retrieve the result of
        monitoring.
        """
        return None

        res = self.post('rti/rtiMon', {
            'cmd': 'Mon',
            'cmdOpt': 'Start',
            'deviceId': device_id,
            'workId': gen_uuid(),
        })
        return res['workId']

    def monitor_poll(self, device_id, work_id):
        """Get the result of a monitoring task.

        `work_id` is a string ID retrieved from `monitor_start`. Return
        a status result, which is a bytestring, or None if the
        monitoring is not yet ready.

        May raise a `MonitorError`, in which case the right course of
        action is probably to restart the monitoring task.
        """

        return None
        work_list = [{'deviceId': device_id, 'workId': work_id}]
        res = self.post('rti/rtiResult', {'workList': work_list})['workList']

        # When monitoring first starts, it usually takes a few
        # iterations before data becomes available. In the initial
        # "warmup" phase, `returnCode` is missing from the response.
        if 'returnCode' not in res:
            return None

        # Check for errors.
        code = res.get('returnCode')  # returnCode can be missing.
        if code != '0000':
            raise MonitorError(device_id, code)

        # The return data may or may not be present, depending on the
        # monitoring task status.
        if 'returnData' in res:
            # The main response payload is base64-encoded binary data in
            # the `returnData` field. This sometimes contains JSON data
            # and sometimes other binary data.
            return base64.b64decode(res['returnData'])
        else:
            return None

    def monitor_stop(self, device_id, work_id):
        """Stop monitoring a device."""
        self.monitor.unsubscribe(device_id)
        return ""
        self.post('rti/rtiMon', {
            'cmd': 'Mon',
            'cmdOpt': 'Stop',
            'deviceId': device_id,
            'workId': work_id,
        })

    def set_device_controls(self, device_id, values):
        """Control a device's settings.

        `values` is a key/value map containing the settings to update.
        """

        return self.post('rti/rtiControl', {
            'cmd': 'Control',
            'cmdOpt': 'Set',
            'value': values,
            'deviceId': device_id,
            'workId': gen_uuid(),
            'data': '',
        })

    def get_device_config(self, device_id, key, category='Config'):
        """Get a device configuration option.

        The `category` string should probably either be "Config" or
        "Control"; the right choice appears to depend on the key.
        """

        res = self.post('rti/rtiControl', {
            'cmd': category,
            'cmdOpt': 'Get',
            'value': key,
            'deviceId': device_id,
            'workId': gen_uuid(),
            'data': '',
        })
        return res['returnData']

    @classmethod
    def load(cls, auth, data):
        session = cls(auth)
        if 'monitor' in data:
            session._monitor = AWSMQTTMonitor.load(data['monitor'])
        return session

    def dump(self):
        return {
            'monitor': self.monitor.dump()
        }

class AWSMQTTAuth(object):
    def __init__(self, ca_cert=None, csr=None, private_key=None, client_cert=None, topic=None):
        if csr is None:
            # TODO - handle exception
            self.ca_cert = requests.get(AWS_IOTT_CA_CERT_URL).text

            key = crypto.PKey()
            key.generate_key(crypto.TYPE_RSA, 2048)
            self.private_key = str(crypto.dump_privatekey(FILETYPE_PEM, key), 'utf8')

            csr = crypto.X509Req()
            csr.get_subject().CN = 'AWS IoT Certificate'
            csr.get_subject().O = 'Amazon'
            csr.set_pubkey(key)
            csr.sign(key, 'sha256')
            self.csr = str(crypto.dump_certificate_request(FILETYPE_PEM, csr), 'utf8')

            self.client_cert = None
            self.topic = None

        else:
            self.ca_cert = ca_cert
            self.csr = csr
            self.private_key = private_key
            self.client_cert = client_cert
            self.topic = topic

    @property
    def client_id(self):
        return self.topic.split("/")[2]

    @property
    def ssl_context(self):
        ca_cert = self.__tempfile(self.ca_cert)
        private_key = self.__tempfile(self.private_key)
        client_cert = self.__tempfile(self.client_cert)

        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.set_alpn_protocols([AWS_IOTT_ALPN_PROTOCOL])
        context.load_cert_chain(certfile=client_cert.name, keyfile=private_key.name)
        context.load_verify_locations(cafile=ca_cert.name)

        return context

    def __tempfile(self, content):
        file = NamedTemporaryFile()
        file.write(content.encode('utf8'))
        file.seek(0)
        return file

    @classmethod
    def from_session(cls, session):
        auth = cls()
        cert_data = session.post('service/users/client/certificate', {
            'csr': auth.csr
        })
        auth.client_cert = cert_data['certificatePem']
        auth.topic = cert_data['subscriptions'][0]
        return auth

    def dump(self):
        data = {}
        if self.ca_cert:
            data['ca_cert'] = self.ca_cert
        if self.csr:
            data['csr'] = self.csr
        if self.private_key:
            data['private_key'] = self.private_key
        if self.client_cert:
            data['client_cert'] = self.client_cert
        if self.topic:
            data['topic'] = self.topic
        return data

    @classmethod
    def load(cls, data):
        return cls(**data)

class AWSMQTTMonitor(object):

    def __init__(self, mqtt_host, mqtt_port, auth):
        self.mqtt_host = mqtt_host
        self.mqtt_port = mqtt_port
        self.auth = auth

        self._subscriptions = []
        self._mqtt = None

    def subscribe(self, device_id):
        if not self._mqtt:
            self.connect()

        self._subscriptions.append(device_id)

    def unsubscribe(self, device_id):
        self._subscriptions.remove(device_id)
        if not self._subscriptions:
            self.disconnect()

    def connect(self):
        def on_connect(client, userdata, flags, rc):
            client.subscribe(self.auth.topic, 1)

        def on_message(client, userdata, msg):
            print(msg.topic+" "+str(msg.payload))

        if not self._mqtt:
            self._mqtt = mqtt.Client(client_id=self.auth.client_id)
            self._mqtt.tls_set_context(self.auth.ssl_context)
            self._mqtt.on_connect = on_connect
            self._mqtt.on_message = on_message

            err = self._mqtt.connect(self.mqtt_host, self.mqtt_port)
            self._mqtt.loop_start()

    def disconnect(self):
        if self._mqtt:
            self._mqtt.loop_stop()
            self._mqtt.disconnect()
            self._mqtt = None

    @classmethod
    def from_session(cls, session):
        auth = AWSMQTTAuth.from_session(session)

        mqtt_endpoint = urlparse(session.mqtt_endpoint)

        # XXX - exception handling
        return cls(
            mqtt_endpoint.hostname,
            mqtt_endpoint.port,
            auth)

    @classmethod
    def load(cls, data):
        return cls(
            data['mqtt_host'],
            data['mqtt_port'],
            AWSMQTTAuth.load(data['auth']))

    def dump(self):
        return {
            'mqtt_host': self.mqtt_host,
            'mqtt_port': self.mqtt_port,
            'auth': self.auth.dump(),
        }
