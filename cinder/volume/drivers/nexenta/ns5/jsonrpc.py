# Copyright 2019 Nexenta by DDN, Inc. All rights reserved.
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

import hashlib
import json
import posixpath

from eventlet import greenthread
from oslo_log import log as logging
import requests
import six

from cinder import exception
from cinder.i18n import _

LOG = logging.getLogger(__name__)

HTTPS_PORT = 8443
HTTP_PORT = 8080
HTTPS = 'https'
HTTP = 'http'
AUTO = 'auto'
NFS = 'nfs'
ISCSI = 'iscsi'


class NefException(exception.VolumeDriverException):
    def __init__(self, data=None, **kwargs):
        defaults = {
            'name': 'NexentaError',
            'code': 'EBADMSG',
            'source': 'CinderDriver',
            'message': 'Unknown error'
        }
        if isinstance(data, dict):
            for key in defaults:
                if key in kwargs:
                    continue
                if key in data:
                    kwargs[key] = data[key]
                else:
                    kwargs[key] = defaults[key]
        elif isinstance(data, six.string_types):
            if 'message' not in kwargs:
                kwargs['message'] = data
        for key in defaults:
            if key not in kwargs:
                kwargs[key] = defaults[key]
        message = ('%(message)s (source: %(source)s, '
                   'name: %(name)s, code: %(code)s)') % kwargs
        self.code = kwargs['code']
        del kwargs['message']
        super(NefException, self).__init__(message, **kwargs)


class NefRequest(object):
    def __init__(self, proxy, method):
        self.proxy = proxy
        self.method = method
        self.attempts = proxy.retries + 1
        self.payload = None
        self.path = None
        self.time = 0
        self.data = []
        self.stat = {}
        self.hooks = {
            'response': self.hook
        }
        self.kwargs = {
            'hooks': self.hooks,
            'timeout': self.proxy.timeout
        }

    def __call__(self, path, payload=None):
        LOG.debug('NEF request start: %(method)s %(path)s %(payload)s',
                  {'method': self.method, 'path': path, 'payload': payload})
        self.path = path
        self.payload = payload
        message = None
        for attempt in range(self.attempts):
            self.data = []
            if message:
                self.proxy.delay(attempt)
                if not self.find_host():
                    continue
                LOG.warning('NEF request retry %(attempt)s: %(method)s '
                            '%(path)s %(payload)s, reason: %(message)s ',
                            {'attempt': attempt, 'method': self.method,
                             'path': path, 'payload': payload,
                             'message': message})
            try:
                response = self.request(self.method, self.path, self.payload)
            except (requests.exceptions.RequestException,
                    NefException) as error:
                message = error
                continue
            LOG.debug('NEF request done: %(method)s %(path)s %(payload)s, '
                      'total response time: %(time)s seconds, '
                      'total requests count: %(count)s, '
                      'requests statistics: %(stat)s, '
                      'response content: %(content)s',
                      {'method': self.method,
                       'path': self.path,
                       'payload': self.payload,
                       'time': self.time,
                       'count': sum(self.stat.values()),
                       'stat': self.stat,
                       'content': response.content})
            if response.ok and not response.content:
                return None
            content = json.loads(response.content)
            if not response.ok:
                raise NefException(content)
            if isinstance(content, dict) and 'data' in content:
                return self.data
            return content
        raise message

    def request(self, method, path, payload):
        if self.method not in ['get', 'delete', 'put', 'post']:
            message = (_('Request method %(method)s not supported')
                       % {'method': self.method})
            raise NefException(code='EINVAL', message=message)
        if not path:
            message = _('Request path is required')
            raise NefException(code='EINVAL', message=message)
        url = self.proxy.url(path)
        kwargs = dict(self.kwargs)
        if payload:
            if not isinstance(payload, dict):
                message = _('Request payload must be a dictionary')
                raise NefException(code='EINVAL', message=message)
            if method in ['get', 'delete']:
                kwargs['params'] = payload
            elif method in ['put', 'post']:
                kwargs['data'] = json.dumps(payload)
        LOG.debug('Session request: %(method)s %(url)s %(data)s',
                  {'method': method, 'url': url, 'data': kwargs})
        return self.proxy.session.request(method, url, **kwargs)

    def hook(self, response, **kwargs):
        text = (_('session request %(method)s %(url)s %(body)s '
                  'and session response %(code)s %(content)s')
                % {'method': response.request.method,
                   'url': response.request.url,
                   'body': response.request.body,
                   'code': response.status_code,
                   'content': response.content})
        LOG.debug('Hook start on %(text)s', {'text': text})
        if response.status_code not in self.stat:
            self.stat[response.status_code] = 0
        self.stat[response.status_code] += 1
        self.time += response.elapsed.total_seconds()
        attempt = self.stat[response.status_code]
        limit = len(self.proxy.hosts) * self.attempts
        if response.ok and not response.content:
            return response
        try:
            content = json.loads(response.content)
        except (TypeError, ValueError) as error:
            message = (_('Failed to decode JSON for %(text)s: %(error)s')
                       % {'text': text, 'error': error})
            raise NefException(code='EINVAL', message=message)
        if response.ok and content is None:
            return response
        if not isinstance(content, dict):
            message = (_('Invalid JSON for %(text)s: not a dictionary')
                       % {'text': text})
            raise NefException(code='EINVAL', message=message)
        if attempt > limit and not response.ok:
            return response
        method = 'get'
        if response.status_code == requests.codes.unauthorized:
            if not self.auth():
                raise NefException(content)
            request = response.request.copy()
            request.headers.update(self.proxy.session.headers)
            return self.proxy.session.send(request, **kwargs)
        elif response.status_code == requests.codes.not_found:
            if not self.check_host():
                raise NefException(content)
            return response
        elif response.status_code == requests.codes.server_error:
            if 'code' in content and content['code'] == 'EBUSY':
                raise NefException(content)
            return response
        elif response.status_code == requests.codes.accepted:
            path, payload = self.parse(content, 'monitor')
            if not path:
                message = (_('Monitor path not found for %(text)s')
                           % {'text': text})
                raise NefException(code='ENODATA', message=message)
            self.proxy.delay(attempt)
            return self.request(method, path, payload)
        elif response.status_code == requests.codes.ok:
            if not ('data' in content and content['data']):
                LOG.debug('Hook done on %(text)s: no JSON data',
                          {'text': text})
                return response
            LOG.debug('Add %(count)s data items to response',
                      {'count': len(content['data'])})
            self.data += content['data']
            path, payload = self.parse(content, 'next')
            if not path:
                LOG.debug('Hook done on %(text)s: no next path',
                          {'text': text})
                return response
            if self.payload:
                payload.update(self.payload)
            LOG.debug('Hook continue with session request '
                      '%(method)s %(path)s %(payload)s',
                      {'method': method, 'path': path,
                       'payload': payload})
            return self.request(method, path, payload)
        LOG.debug('Hook done on %(text)s', {'text': text})
        return response

    def auth(self):
        method = 'post'
        path = '/auth/login'
        payload = {
            'username': self.proxy.username,
            'password': self.proxy.password
        }
        self.proxy.delete_bearer()
        response = self.request(method, path, payload)
        content = json.loads(response.content)
        if 'token' in content:
            self.proxy.update_token(content['token'])
            return True
        return False

    def check_host(self):
        method = 'get'
        path = self.proxy.root
        payload = {
            'path': self.proxy.path,
            'fields': 'path'
        }
        response = self.request(method, path, payload)
        content = json.loads(response.content)
        if 'data' in content and content['data']:
            return True
        return False

    def find_host(self):
        for host in self.proxy.hosts:
            self.proxy.update_host(host)
            LOG.debug('Try to failover to host %(host)s',
                      {'host': host})
            try:
                if self.check_host():
                    return True
            except (requests.exceptions.RequestException,
                    NefException) as error:
                LOG.debug('Skip host %(host)s, reason: %(error)s',
                          {'host': host, 'error': error})
        return False

    @staticmethod
    def parse(content, name):
        if 'links' in content:
            links = content['links']
            if isinstance(links, list):
                for link in links:
                    if (isinstance(link, dict) and
                            'href' in link and
                            'rel' in link and
                            link['rel'] == name):
                        url = six.moves.urllib.parse.urlparse(link['href'])
                        payload = six.moves.urllib.parse.parse_qs(url.query)
                        return url.path, payload
        return None, None


class NefCollections(object):

    def __init__(self, proxy):
        self.proxy = proxy
        self.namespace = 'nexenta'
        self.prefix = 'instance'
        self.root = '/collections'
        self.subj = 'collection'
        self.properties = []

    def path(self, name):
        quoted_name = six.moves.urllib.parse.quote_plus(name)
        return posixpath.join(self.root, quoted_name)

    def key(self, name):
        return '%s:%s_%s' % (self.namespace, self.prefix, name)

    def get(self, name, payload=None):
        LOG.debug('Get properties of %(subj)s %(name)s: %(payload)s',
                  {'subj': self.subj, 'name': name, 'payload': payload})
        path = self.path(name)
        return self.proxy.get(path, payload)

    def set(self, name, payload=None):
        LOG.debug('Modify properties of %(subj)s %(name)s: %(payload)s',
                  {'subj': self.subj, 'name': name, 'payload': payload})
        path = self.path(name)
        return self.proxy.put(path, payload)

    def list(self, payload=None):
        LOG.debug('List of %(subj)ss: %(payload)s',
                  {'subj': self.subj, 'payload': payload})
        return self.proxy.get(self.root, payload)

    def create(self, payload=None):
        LOG.debug('Create %(subj)s: %(payload)s',
                  {'subj': self.subj, 'payload': payload})
        try:
            return self.proxy.post(self.root, payload)
        except NefException as error:
            if error.code != 'EEXIST':
                raise

    def delete(self, name, payload=None):
        LOG.debug('Delete %(subj)s %(name)s: %(payload)s',
                  {'subj': self.subj, 'name': name, 'payload': payload})
        path = self.path(name)
        try:
            return self.proxy.delete(path, payload)
        except NefException as error:
            if error.code != 'ENOENT':
                raise


class NefSettings(NefCollections):

    def __init__(self, proxy):
        super(NefSettings, self).__init__(proxy)
        self.root = '/settings/properties'
        self.subj = 'setting'

    def create(self, payload=None):
        return NotImplemented

    def delete(self, name, payload=None):
        return NotImplemented


class NefDatasets(NefCollections):

    def __init__(self, proxy):
        super(NefDatasets, self).__init__(proxy)
        self.root = '/storage/datasets'
        self.subj = 'dataset'

    def rename(self, name, payload=None):
        LOG.debug('Rename %(subj)s %(name)s: %(payload)s',
                  {'subj': self.subj, 'name': name, 'payload': payload})
        path = posixpath.join(self.path(name), 'rename')
        return self.proxy.post(path, payload)


class NefSnapshots(NefDatasets, NefCollections):

    def __init__(self, proxy):
        super(NefSnapshots, self).__init__(proxy)
        self.root = '/storage/snapshots'
        self.subj = 'snapshot'

    def clone(self, name, payload=None):
        LOG.debug('Clone %(subj)s %(name)s: %(payload)s',
                  {'subj': self.subj, 'name': name, 'payload': payload})
        path = posixpath.join(self.path(name), 'clone')
        return self.proxy.post(path, payload)


class NefVolumeGroups(NefDatasets, NefCollections):

    def __init__(self, proxy):
        super(NefVolumeGroups, self).__init__(proxy)
        self.root = '/storage/volumeGroups'
        self.subj = 'volume group'

    def rollback(self, name, payload=None):
        LOG.debug('Rollback %(subj)s %(name)s: %(payload)s',
                  {'subj': self.subj, 'name': name, 'payload': payload})
        path = posixpath.join(self.path(name), 'rollback')
        return self.proxy.post(path, payload)


class NefVolumes(NefVolumeGroups, NefDatasets, NefCollections):

    def __init__(self, proxy):
        super(NefVolumes, self).__init__(proxy)
        self.prefix = 'volume'
        self.root = '/storage/volumes'
        self.subj = 'volume'
        self.properties = [
            {
                'name': self.key('blocksize'),
                'api': 'volumeBlockSize',
                'cfg': 'nexenta_blocksize',
                'title': 'Block size',
                'retype': _('Volume block size cannot be changed after '
                            'the volume has been created.'),
                'description': _('Controls the block size of a volume.'),
                'type': 'integer',
                'enum': [512, 1024, 2048, 4096, 8192,
                         16384, 32768, 65536, 131072],
                'default': 32768
            },
            {
                'name': self.key('checksum'),
                'api': 'checksumMode',
                'title': 'Data integrity mode',
                'description': _('Controls the checksum algorithm used to '
                                 'verify volume data integrity.'),
                'type': 'string',
                'enum': ['on', 'off', 'fletcher2', 'fletcher4', 'sha256'],
                'default': 'on'
            },
            {
                'name': self.key('compression'),
                'api': 'compressionMode',
                'cfg': 'nexenta_dataset_compression',
                'title': 'Data compression mode',
                'description': _('Controls the compression algorithm used '
                                 'to compress volume data.'),
                'type': 'string',
                'enum': ['off', 'on', 'lz4', 'lzjb', 'zle', 'gzip', 'gzip-1',
                         'gzip-2', 'gzip-3', 'gzip-4', 'gzip-5', 'gzip-6',
                         'gzip-7', 'gzip-8', 'gzip-9'],
                'default': 'lz4'
            },
            {
                'name': self.key('copies'),
                'api': 'dataCopies',
                'title': 'Number of data copies',
                'description': _('Controls the number of copies of volume '
                                 'data.'),
                'type': 'integer',
                'enum': [1, 2, 3],
                'default': 1
            },
            {
                'name': self.key('dedup'),
                'api': 'dedupMode',
                'cfg': 'nexenta_dataset_dedup',
                'title': 'Data deduplication mode',
                'description': _('Controls the deduplication algorithm used '
                                 'to verify volume data integrity.'),
                'type': 'string',
                'enum': ['off', 'on', 'verify', 'sha256', 'sha256,verify'],
                'default': 'off'
            },
            {
                'name': self.key('logbias'),
                'api': 'logBiasMode',
                'title': 'Log bias mode',
                'description': _('Provides a hint about handling of '
                                 'synchronous requests for a volume.'),
                'type': 'string',
                'enum': ['latency', 'throughput'],
                'default': 'latency'
            },
            {
                'name': self.key('primarycache'),
                'api': 'primaryCacheMode',
                'title': 'Primary cache mode',
                'description': _('Controls what is cached in the primary '
                                 'cache (ARC).'),
                'type': 'string',
                'enum': ['all', 'none', 'metadata'],
                'default': 'all'
            },
            {
                'name': self.key('readonly'),
                'api': 'readOnly',
                'title': 'Read-only mode',
                'description': _('Controls whether a volume can be modified.'),
                'type': 'boolean',
                'default': False
            },
            {
                'name': self.key('redundant_metadata'),
                'api': 'redundantMetadata',
                'title': 'Metadata redundancy mode',
                'description': _('Controls what types of metadata are stored '
                                 'redundantly.'),
                'type': 'string',
                'enum': ['all', 'most'],
                'default': 'all'
            },
            {
                'name': self.key('secondarycache'),
                'api': 'secondaryCache',
                'title': 'Secondary cache',
                'description': _('Controls what is cached in the secondary '
                                 'cache (L2ARC).'),
                'type': 'string',
                'enum': ['all', 'none', 'metadata'],
                'default': 'all'
            },
            {
                'name': self.key('thin_provisioning'),
                'api': 'sparseVolume',
                'cfg': 'nexenta_sparsed_volumes',
                'title': 'Thin provisioning',
                'inherit': _('Provisioning type cannot be inherit.'),
                'description': _('Controls if a volume is created sparse '
                                 '(with no space reservation).'),
                'type': 'boolean',
                'default': True
            },
            {
                'name': self.key('sync'),
                'api': 'syncMode',
                'title': 'Sync mode',
                'description': _('Controls the behavior of synchronous '
                                 'requests to a volume.'),
                'type': 'string',
                'enum': ['standard', 'always', 'disabled'],
                'default': 'standard'
            },
            {
                'name': self.key('write_back_cache'),
                'api': 'writeBackCache',
                'title': 'Write-back cache mode',
                'inherit': _('Write-back cache mode cannot be inherit.'),
                'description': _('Controls if the ZFS write-back cache '
                                 'is enabled for a volume.'),
                'type': 'boolean',
                'default': False
            },
            {
                'name': self.key('zpl_meta_to_metadev'),
                'api': 'zplMetaToMetadev',
                'title': 'ZPL metadata placement behavior',
                'description': _('Control ZFS POSIX metadata placement '
                                 'to a special virtual device.'),
                'type': 'string',
                'enum': ['off', 'on', 'dual'],
                'default': 'off'
            }
        ]

    def promote(self, name, payload=None):
        LOG.debug('Promote %(subj)s %(name)s: %(payload)s',
                  {'subj': self.subj, 'name': name, 'payload': payload})
        path = posixpath.join(self.path(name), 'promote')
        return self.proxy.post(path, payload)


class NefFilesystems(NefVolumes, NefVolumeGroups, NefDatasets, NefCollections):

    def __init__(self, proxy):
        super(NefFilesystems, self).__init__(proxy)
        self.root = '/storage/filesystems'
        self.subj = 'filesystem'
        for prop in self.properties:
            if prop['name'] == self.key('blocksize'):
                del prop['retype']
                prop['api'] = 'recordSize'
                prop['description'] = _('Specifies a suggested block size '
                                        'for a volume.')
                prop['enum'] = [512, 1024, 2048, 4096, 8192, 16384, 32768,
                                65536, 131072, 262144, 524288, 1048576]
        self.properties.append({
            'name': self.key('rate_limit'),
            'api': 'rateLimit',
            'title': 'Transfer rate limit',
            'description': _('Controls a transfer rate limit '
                             '(bytes per second) for a volume.'),
            'type': 'integer',
            'default': 0
        })
        self.properties.append({
            'name': self.key('nbmand'),
            'api': 'nonBlockingMandatoryMode',
            'title': 'Non-blocking mandatory locking',
            'description': _('Allow or disallow non-blocking mandatory '
                             'locking semantics for a volume.'),
            'type': 'boolean',
            'default': False
        })
        self.properties.append({
            'name': self.key('smart_compression'),
            'api': 'smartCompression',
            'title': 'Smart compression',
            'description': _('Allow or disallow dynamically tracks volume '
                             'compression ratios to determine if a volume '
                             'data is compressible or not.'),
            'type': 'boolean',
            'default': False
        })
        self.properties.append({
            'name': self.key('snapdir'),
            'api': 'snapshotDirectory',
            'title': '.zfs directory visibility',
            'description': _('Controls whether the .zfs directory '
                             'is hidden or visible in the root of '
                             'the volume file system.'),
            'type': 'boolean',
            'default': False
        })
        self.properties.append({
            'name': self.key('format'),
            'api': 'volumeFormat',
            'cfg': 'nexenta_volume_format',
            'title': 'Volume format',
            'description': _('Controls volume format.'),
            'enum': ['raw', 'qcow', 'qcow2', 'parallels',
                     'vdi', 'vhdx', 'vmdk', 'vpc', 'qed'],
            'type': 'string',
            'default': 'raw'
        })

    def mount(self, name, payload=None):
        LOG.debug('Mount %(subj)s %(name)s: %(payload)s',
                  {'subj': self.subj, 'name': name, 'payload': payload})
        path = posixpath.join(self.path(name), 'mount')
        return self.proxy.post(path, payload)

    def unmount(self, name, payload=None):
        LOG.debug('Unmount %(subj)s %(name)s: %(payload)s',
                  {'subj': self.subj, 'name': name, 'payload': payload})
        path = posixpath.join(self.path(name), 'unmount')
        return self.proxy.post(path, payload)

    def acl(self, name, payload=None):
        LOG.debug('Set %(subj)s %(name)s ACL: %(payload)s',
                  {'subj': self.subj, 'name': name, 'payload': payload})
        path = posixpath.join(self.path(name), 'acl')
        return self.proxy.post(path, payload)


class NefHpr(NefCollections):

    def __init__(self, proxy):
        super(NefHpr, self).__init__(proxy)
        self.root = '/hpr/services'
        self.subj = 'HPR service'

    def activate(self, payload=None):
        LOG.debug('Activate %(payload)s',
                  {'payload': payload})
        root = posixpath.dirname(self.root)
        path = posixpath.join(root, 'activate')
        return self.proxy.post(path, payload)

    def start(self, name, payload=None):
        LOG.debug('Start %(subj)s %(name)s: %(payload)s',
                  {'subj': self.subj, 'name': name, 'payload': payload})
        path = posixpath.join(self.path(name), 'start')
        return self.proxy.post(path, payload)


class NefRsf(NefCollections):

    def __init__(self, proxy):
        super(NefRsf, self).__init__(proxy)
        self.root = '/rsf/clusters'
        self.subj = 'RSF Clusters'


class NefServices(NefCollections):

    def __init__(self, proxy):
        super(NefServices, self).__init__(proxy)
        self.root = '/services'
        self.subj = 'service'


class NefNfs(NefCollections):

    def __init__(self, proxy):
        super(NefNfs, self).__init__(proxy)
        self.root = '/nas/nfs'
        self.subj = 'NFS'


class NefTargets(NefCollections):

    def __init__(self, proxy):
        super(NefTargets, self).__init__(proxy)
        self.root = '/san/iscsi/targets'
        self.subj = 'iSCSI target'


class NefHostGroups(NefCollections):

    def __init__(self, proxy):
        super(NefHostGroups, self).__init__(proxy)
        self.root = '/san/hostgroups'
        self.subj = 'host group'


class NefTargetsGroups(NefCollections):

    def __init__(self, proxy):
        super(NefTargetsGroups, self).__init__(proxy)
        self.root = '/san/targetgroups'
        self.subj = 'target group'


class NefLunMappings(NefCollections):

    def __init__(self, proxy):
        super(NefLunMappings, self).__init__(proxy)
        self.root = '/san/lunMappings'
        self.subj = 'LUN mapping'


class NefLogicalUnits(NefCollections):

    def __init__(self, proxy):
        super(NefLogicalUnits, self).__init__(proxy)
        self.prefix = 'logical_unit'
        self.root = '/san/logicalUnits'
        self.subj = 'logical unit'
        self.properties = [
            {
                'name': self.key('writeback_cache_disabled'),
                'api': 'writebackCacheDisabled',
                'cfg': 'nexenta_lu_writebackcache_disabled',
                'title': 'Logical unit write-back cache disable mode',
                'description': _('Controls logical unit write-back '
                                 'cache disable behavior.'),
                'type': 'boolean',
                'default': False
            },
            {
                'name': self.key('write_protect'),
                'api': 'writeProtect',
                'title': 'Logical unit write protect mode',
                'description': _('Controls logical unit write '
                                 'protection behavior.'),
                'type': 'boolean',
                'default': False
            }
        ]


class NefNetAddresses(NefCollections):

    def __init__(self, proxy):
        super(NefNetAddresses, self).__init__(proxy)
        self.root = '/network/addresses'
        self.subj = 'network address'


class NefProxy(object):
    def __init__(self, proto, path, conf):
        self.settings = NefSettings(self)
        self.filesystems = NefFilesystems(self)
        self.volumegroups = NefVolumeGroups(self)
        self.volumes = NefVolumes(self)
        self.snapshots = NefSnapshots(self)
        self.services = NefServices(self)
        self.hpr = NefHpr(self)
        self.rsf = NefRsf(self)
        self.nfs = NefNfs(self)
        self.targets = NefTargets(self)
        self.hostgroups = NefHostGroups(self)
        self.targetgroups = NefTargetsGroups(self)
        self.mappings = NefLunMappings(self)
        self.logicalunits = NefLogicalUnits(self)
        self.netaddrs = NefNetAddresses(self)
        self.lock = None
        self.auto = False
        self.tokens = {}
        self.headers = {
            'Content-Type': 'application/json',
            'X-XSS-Protection': '1'
        }
        if proto == NFS:
            self.root = self.filesystems.root
        elif proto == ISCSI:
            self.root = self.volumegroups.root
        else:
            message = (_('Storage protocol %(proto)s not supported')
                       % {'proto': proto})
            raise NefException(code='EPROTO', message=message)
        if conf.nexenta_use_https is None:
            self.scheme = conf.nexenta_rest_protocol
            if self.scheme == AUTO:
                self.auto = True
                self.scheme = HTTPS
        else:
            if conf.nexenta_use_https:
                self.scheme = HTTPS
            else:
                self.scheme = HTTP
        if conf.nexenta_rest_port:
            self.port = conf.nexenta_rest_port
        else:
            if self.scheme == HTTPS:
                self.port = HTTPS_PORT
            else:
                self.port = HTTP_PORT
        self.username = conf.nexenta_user
        self.password = conf.nexenta_password
        self.hosts = []
        if conf.nexenta_rest_address:
            for host in conf.nexenta_rest_address.split(','):
                self.hosts.append(host.strip())
        elif proto == ISCSI and conf.nexenta_host:
            self.hosts.append(conf.nexenta_host)
        elif proto == NFS and conf.nas_host:
            self.hosts.append(conf.nas_host)
        else:
            message = (_('NexentaStor Rest API address is not defined, '
                         'please check the Cinder configuration file for '
                         'NexentaStor backend and nexenta_rest_address, '
                         'nexenta_host or nas_host configuration options'))
            raise NefException(code='EINVAL', message=message)
        self.host = self.hosts[0]
        self.path = path
        self.retries = conf.nexenta_rest_retry_count
        self.backoff_factor = conf.nexenta_rest_backoff_factor
        self.timeout = (conf.nexenta_rest_connect_timeout,
                        conf.nexenta_rest_read_timeout)
        self.session = requests.Session()
        self.session.verify = conf.driver_ssl_cert_verify
        if self.session.verify and conf.driver_ssl_cert_path:
            self.session.verify = conf.driver_ssl_cert_path
        self.session.headers.update(self.headers)
        if not conf.driver_ssl_cert_verify:
            requests.packages.urllib3.disable_warnings()
        self.update_lock()

    def __getattr__(self, name):
        return NefRequest(self, name)

    def delete_bearer(self):
        if 'Authorization' in self.session.headers:
            del self.session.headers['Authorization']

    def update_bearer(self, token):
        bearer = 'Bearer %s' % token
        self.session.headers['Authorization'] = bearer

    def update_token(self, token):
        self.tokens[self.host] = token
        self.update_bearer(token)

    def update_host(self, host):
        self.host = host
        if host in self.tokens:
            token = self.tokens[host]
            self.update_bearer(token)

    def update_lock(self):
        settings = {}
        guid = None
        try:
            settings = self.settings.get('system.guid')
        except NefException as error:
            LOG.error('Unable to get host settings: %(error)s',
                      {'error': error})
        if settings and 'value' in settings:
            guid = settings['value']
            LOG.debug('Host guid: %(guid)s', {'guid': guid})
        else:
            LOG.error('Unable to get host guid: %(settings)s',
                      {'settings': settings})
        guids = []
        clusters = []
        payload = {'fields': 'nodes'}
        try:
            clusters = self.rsf.list(payload)
        except NefException as error:
            LOG.error('Unable to get HA cluster guid: %(error)s',
                      {'error': error})
        for cluster in clusters:
            if 'nodes' not in cluster:
                continue
            nodes = cluster['nodes']
            for node in nodes:
                if 'machineId' in node:
                    guids.append(node['machineId'])
        if guid in guids:
            guid = ':'.join(sorted(guids))
            LOG.debug('HA cluster guid: %(guid)s',
                      {'guid': guid})
        if not guid:
            guid = ':'.join(sorted(self.hosts))
        lock = '%s:%s' % (guid, self.path)
        if six.PY3:
            lock = lock.encode('utf-8')
        self.lock = hashlib.md5(lock).hexdigest()
        LOG.debug('NEF coordination lock: %(lock)s',
                  {'lock': self.lock})

    def url(self, path=''):
        netloc = '%s:%d' % (self.host, self.port)
        components = (self.scheme, netloc, path, None, None)
        url = six.moves.urllib.parse.urlunsplit(components)
        return url

    def delay(self, attempt):
        interval = float(self.backoff_factor * (2 ** (attempt - 1)))
        LOG.debug('Waiting for %(interval)s seconds',
                  {'interval': interval})
        greenthread.sleep(interval)
