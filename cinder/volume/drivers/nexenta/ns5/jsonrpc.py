# Copyright 2018 Nexenta Systems, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import json
import requests
import six
import time

from cinder.openstack.common import log as logging

from cinder import exception
from cinder.i18n import _
from cinder.volume.drivers.nexenta import utils
from requests.cookies import extract_cookies_to_jar

LOG = logging.getLogger(__name__)
TIMEOUT = 60
APPLIANCE ='NexentaStor Appliance'

def check_error(response):
    code = response.status_code
    if code not in (200, 201, 202):
        reason = response.reason
        body = response.content
        try:
            content = json.loads(body) if body else None
        except ValueError:
            msg = (_('Could not parse response from %(appliance)s: '
                     '%(code)s %(reason)s %(body)s')
                   % {'appliance': APPLIANCE,
                      'code': code,
                      'reason': reason,
                      'body': body})
            raise exception.NexentaException(msg)
        if content and 'code' in content:
            raise exception.NexentaException(content)
        msg = (_('Got bad response from %(appliance)s: '
                 '%(code)s %(reason)s %(content)s')
               % {'appliance': APPLIANCE,
                  'code': code,
                  'reason': reason,
                  'content': content})
        raise exception.NexentaException(msg)

class RESTCaller(object):

    def __init__(self, proxy, method):
        self.__proxy = proxy
        self.__method = method

    def get_full_url(self, path):
        return '/'.join((self.__proxy.url, path))

    def __call__(self, *args):
        url = self.get_full_url(args[0])
        kwargs = {'timeout': TIMEOUT, 'verify': self.__proxy.verify}
        data = None
        if len(args) > 1:
            kwargs['data'] = json.dumps(args[1])
            data = args[1]

        LOG.debug('Issuing call to %(appliance)s: '
                  '%(url)s %(method)s data: %(data)s',
                  {'appliance': APPLIANCE,
                   'url': url,
                   'method': self.__method,
                   'data': data})

        try:
            response = getattr(
                self.__proxy.session, self.__method)(url, **kwargs)
        except requests.exceptions.ConnectionError:
            LOG.warning('Connection error on call to %(appliance)s: '
                        '%(url)s %(method)s data: %(data)s',
                        {'appliance': APPLIANCE,
                         'url': self.__proxy.url,
                         'method': self.__method,
                         'data': data})
            self.handle_failover()
            url = self.get_full_url(args[0])
            response = getattr(
                self.__proxy.session, self.__method)(url, **kwargs)
        try:
            check_error(response)
        except exception.NexentaException as ex:
            err = utils.ex2err(ex)
            if err['code'] == 'ENOENT':
                LOG.warning('Exception on call to %(appliance)s: '
                            '%(url)s %(method)s data: %(data)s '
                            'returned message: %(message)s',
                            {'appliance': APPLIANCE,
                             'url': url,
                             'method': self.__method,
                             'data': data,
                             'message': six.text_type(err)})
                self.handle_failover()
                url = self.get_full_url(args[0])
                response = getattr(
                    self.__proxy.session, self.__method)(url, **kwargs)
            else:
                raise
        check_error(response)
        content = json.loads(response.content) if response.content else None
        LOG.debug('Got response from %(appliance)s: '
                  '%(code)s %(reason)s %(content)s',
                  {'appliance': APPLIANCE,
                   'code': response.status_code,
                   'reason': response.reason,
                   'content': content})

        if response.status_code == 202 and content:
            url = self.get_full_url(content['links'][0]['href'])
            keep_going = True
            while keep_going:
                time.sleep(1)
                response = self.__proxy.session.get(
                    url, verify=self.__proxy.verify)
                try:
                    check_error(response)
                except exception.NexentaException as ex:
                    err = utils.ex2err(ex)
                    if err['code'] == 'ENOENT':
                        LOG.debug('Exception on call to %(appliance)s: '
                                  '%(url)s %(method)s data: %(data)s '
                                  'returned message: %(message)s',
                                  {'appliance': APPLIANCE,
                                   'url': url,
                                   'method': self.__method,
                                   'data': data,
                                   'message': six.text_type(err)})
                        self.handle_failover()
                        url = self.get_full_url(args[0])
                        response = getattr(
                            self.__proxy.session, self.__method)(url, **kwargs)
                    else:
                        raise
                LOG.debug('Got response from %(appliance)s: '
                          '%(code)s %(reason)s',
                          {'appliance': APPLIANCE,
                           'code': response.status_code,
                           'reason': response.reason})
                content = response.json() if response.content else None
                keep_going = response.status_code == 202
        return content

    def handle_failover(self):
        if self.__proxy.backup:
            LOG.info('Primary %(appliance)s %(host)s is unavailable, '
                     'failing over to secondary %(backup)s',
                     {'appliance': APPLIANCE,
                      'host': self.__proxy.host,
                      'backup': self.__proxy.backup})
            host = '%s,%s' % (self.__proxy.backup, self.__proxy.host)
            self.__proxy.__init__(
                host, self.__proxy.port, self.__proxy.user,
                self.__proxy.password, self.__proxy.use_https,
                self.__proxy.pool, self.__proxy.verify)
            url = self.get_full_url('rsf/clusters')
            response = self.__proxy.session.get(
                url, verify=self.__proxy.verify)
            content = response.json() if response.content else None
            if not content:
                raise exception.NexentaException(response)
            cluster_name = content['data'][0]['clusterName']
            for node in content['data'][0]['nodes']:
                if node['ipAddress'] == self.__proxy.host:
                    node_name = node['machineName']
            counter = 0
            interval = 5
            url = self.get_full_url(
                'rsf/clusters/%s/services' % cluster_name)
            while counter < 24:
                counter += 1
                response = self.__proxy.session.get(
                    url, verify=self.__proxy.verify)
                content = response.json() if response.content else None
                if content:
                    for service in content['data']:
                        if service['serviceName'] == self.__proxy.pool:
                            if len(service['vips']) == 0:
                                continue
                            for mapping in service['vips'][0]['nodeMapping']:
                                if (mapping['node'] == node_name and
                                        mapping['status'] == 'up'):
                                    return
                LOG.debug('Pool %(pool)s service is not ready, '
                          'sleeping for %(interval)ss',
                          {'pool': self.__proxy.pool,
                           'interval': interval})
                time.sleep(interval)
            msg = (_('Waited for %(period)ss, but pool %(pool)s '
                     'service is still not running')
                   % {'period': counter * interval,
                      'pool': self.__proxy.pool})
            raise exception.NexentaException(msg)
        else:
            raise


class HTTPSAuth(requests.auth.AuthBase):

    def __init__(self, url, username, password, verify):
        self.url = url
        self.username = username
        self.password = password
        self.token = None
        self.verify = verify

    def __eq__(self, other):
        return all([
            self.url == getattr(other, 'url', None),
            self.username == getattr(other, 'username', None),
            self.password == getattr(other, 'password', None),
            self.token == getattr(other, 'token', None)
        ])

    def __ne__(self, other):
        return not self == other

    def handle_401(self, r, **kwargs):
        if r.status_code == 401:
            LOG.debug('Got [401] response from %(appliance)s: '
                      'trying to reauthenticate ...',
                      {'appliance': APPLIANCE})
            self.token = self.https_auth()
            # Consume content and release the original connection
            # to allow our new request to reuse the same one.
            r.content
            r.close()
            prep = r.request.copy()
            extract_cookies_to_jar(prep._cookies, r.request, r.raw)
            prep.prepare_cookies(prep._cookies)

            prep.headers['Authorization'] = 'Bearer %s' % self.token
            _r = r.connection.send(prep, **kwargs)
            _r.history.append(r)
            _r.request = prep

            return _r
        return r

    def __call__(self, r):
        if not self.token:
            self.token = self.https_auth()
        r.headers['Authorization'] = 'Bearer %s' % self.token
        r.register_hook('response', self.handle_401)
        return r

    def https_auth(self):
        LOG.debug('Sending auth request to %(appliance)s: %(url)s',
                  {'appliance': APPLIANCE,
                   'url': self.url})
        url = '/'.join((self.url, 'auth/login'))
        headers = {'Content-Type': 'application/json'}
        data = {'username': self.username, 'password': self.password}
        response = requests.post(
            url, data=json.dumps(data), verify=self.verify,
            headers=headers, timeout=TIMEOUT)
        content = json.loads(response.content) if response.content else None
        LOG.debug('Auth response from %(appliance)s: '
                  '%(code)s %(reason)s %(content)s',
                  {'appliance': APPLIANCE,
                   'code': response.status_code,
                   'reason': response.reason,
                   'content': content})
        check_error(response)
        response.close()
        if response.content:
            token = content['token']
            del content['token']
            return token
        msg = (_('Got bad response from %(appliance)s: '
                 '%(code)s %(reason)s')
               % {'appliance': APPLIANCE,
                  'code': response.status_code,
                  'reason': response.reason})
        raise exception.NexentaException(msg)

class NexentaJSONProxy(object):

    def __init__(self, host, port, user, password, use_https, pool, verify):
        self.session = requests.Session()
        self.session.headers.update({'Content-Type': 'application/json'})
        self.pool = pool
        self.user = user
        self.verify = verify
        self.password = password
        self.use_https = use_https
        parts = host.split(',')
        self.host = parts[0].strip()
        self.backup = parts[1].strip() if len(parts) > 1 else None
        if use_https:
            self.scheme = 'https'
            self.port = port if port else 8443
            self.session.auth = HTTPSAuth(self.url, user, password, verify)
        else:
            self.scheme = 'http'
            self.port = port if port else 8080
            self.session.auth = (user, password)

    @property
    def url(self):
        return '{}://{}:{}'.format(self.scheme, self.host, self.port)

    def __getattr__(self, name):
        if name in ('get', 'post', 'put', 'delete'):
            return RESTCaller(self, name)
        return super(NexentaJSONProxy, self).__getattribute__(name)

    def __repr__(self):
        return 'HTTP JSON proxy: %s' % self.url
