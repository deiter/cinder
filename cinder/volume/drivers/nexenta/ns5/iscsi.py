# Copyright 2020 Nexenta by DDN, Inc. All rights reserved.
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

import ipaddress
import posixpath
import random
import uuid

from oslo_log import log as logging
from oslo_utils import strutils
from oslo_utils import units
import six

from cinder import coordination
from cinder.i18n import _
from cinder.image import image_utils
from cinder import interface
from cinder import objects
from cinder.volume import driver
from cinder.volume.drivers.nexenta.ns5 import jsonrpc
from cinder.volume.drivers.nexenta import options
from cinder.volume.drivers.nexenta import utils
from cinder.volume import utils as volume_utils
from cinder.volume import volume_types

LOG = logging.getLogger(__name__)

DEFAULT_ISCSI_PORT = 3260
DEFAULT_HOST_GROUP = 'all'
DEFAULT_TARGET_GROUP = 'all'


@interface.volumedriver
class NexentaISCSIDriver(driver.ISCSIDriver):
    """Executes volume driver commands on Nexenta Appliance.

    Version history:

    .. code-block:: none

        1.0.0 - Initial driver version.
        1.1.0 - Added HTTPS support.
              - Added use of sessions for REST calls.
              - Added abandoned volumes and snapshots cleanup.
        1.2.0 - Failover support.
        1.2.1 - Configurable luns per parget, target prefix.
        1.3.0 - Removed target/TG caching, added support for target portals
                and host groups.
        1.3.1 - Refactored _do_export to query exact lunMapping.
        1.3.3 - Refactored LUN creation, use host group for LUN mappings.
        1.3.4 - Adapted NexentaException for the latest Cinder.
        1.3.5 - Added deferred deletion for snapshots.
        1.3.6 - Fixed race between volume/clone deletion.
        1.3.7 - Added consistency group support.
        1.3.8 - Added volume multi-attach.
        1.4.0 - Refactored iSCSI driver.
              - Added pagination support.
              - Added configuration parameters for REST API connect/read
                timeouts, connection retries and backoff factor.
              - Fixed HA failover.
              - Added retries on EBUSY errors.
              - Fixed HTTP authentication.
              - Added coordination for dataset operations.
        1.4.1 - Support for NexentaStor tenants.
        1.4.2 - Added manage/unmanage/manageable-list volume/snapshot support.
        1.4.3 - Added consistency group capability to generic volume group.
        1.4.4 - Added storage assisted volume migration.
                Added support for volume retype.
                Added support for volume type extra specs.
                Added vendor capabilities support.
        1.4.5 - Added report discard support.
        1.4.6 - Added workaround for pagination.
        1.4.7 - Improved error messages.
              - Improved compatibility with initial driver versions.
              - Added throttle for storage assisted volume migration.
        1.4.8 - Fixed renaming volume after generic migration.
              - Fixed properties for volumes created from snapshot.
              - Added workaround for referenced reservation size.
              - Allow retype volume to another provisioning type.
        1.4.9 - Added image caching using clone_image method.
        1.5.0 - Added flag backend_state to report backend status.
              - Added retry on driver initialization failure.
        1.5.1 - Support for location header.
        1.5.2 - Fixed list manageable volumes.
        1.5.3 - Fixed concurrency issues.
    """

    VERSION = '1.5.3'
    CI_WIKI_NAME = "Nexenta_CI"

    vendor_name = 'Nexenta'
    product_name = 'NexentaStor5'
    storage_protocol = 'iSCSI'
    driver_volume_type = 'iscsi'

    def __init__(self, *args, **kwargs):
        super(NexentaISCSIDriver, self).__init__(*args, **kwargs)
        if not self.configuration:
            code = 'ENODATA'
            message = (_('%(product_name)s %(storage_protocol)s '
                         'backend configuration not found')
                       % {'product_name': self.product_name,
                          'storage_protocol': self.storage_protocol})
            raise jsonrpc.NefException(code=code, message=message)
        self.configuration.append_config_values(
            options.NEXENTASTOR5_ISCSI_OPTS)
        self.nef = None
        self.ctxt = None
        self.san_host = None
        self.san_port = None
        self.san_stat = None
        self.san_portals = []
        self.backend_name = self._get_backend_name()
        self.san_driver = self.__class__.__name__
        self.image_cache = self.configuration.nexenta_image_cache
        self.target_prefix = self.configuration.nexenta_target_prefix
        self.targetgroup_prefix = (
            self.configuration.nexenta_target_group_prefix)
        self.block_size = self.configuration.nexenta_blocksize
        self.host_group_prefix = self.configuration.nexenta_host_group_prefix
        self.luns_per_target = self.configuration.nexenta_luns_per_target
        self.lu_writebackcache_disabled = (
            self.configuration.nexenta_lu_writebackcache_disabled)
        self.san_path = posixpath.join(
            self.configuration.nexenta_volume,
            self.configuration.nexenta_volume_group)
        self.san_pool = self.configuration.nexenta_volume
        self.group_snapshot_template = (
            self.configuration.nexenta_group_snapshot_template)
        self.origin_snapshot_template = (
            self.configuration.nexenta_origin_snapshot_template)
        self.cache_image_template = (
            self.configuration.nexenta_cache_image_template)
        self.cache_snapshot_template = (
            self.configuration.nexenta_cache_snapshot_template)
        self.migration_service_prefix = (
            self.configuration.nexenta_migration_service_prefix)
        self.migration_throttle = (
            self.configuration.nexenta_migration_throttle)

    def do_setup(self, ctxt):
        self.ctxt = ctxt
        retries = 0
        while not self._do_setup():
            retries += 1
            self.nef.delay(retries)

    def _do_setup(self):
        try:
            self.nef = jsonrpc.NefProxy(
                self.driver_volume_type,
                self.san_pool,
                self.san_path,
                self.backend_name,
                self.configuration)
        except jsonrpc.NefException as error:
            LOG.error('Failed to initialize RESTful API for backend '
                      '%(backend_name)s on host %(host)s: %(error)s',
                      {'backend_name': self.backend_name,
                       'host': self.host, 'error': error})
            return False
        return True

    def check_for_setup_error(self):
        host = self.configuration.nexenta_host
        port = self.configuration.nexenta_iscsi_target_portal_port
        if host:
            if not port:
                port = DEFAULT_ISCSI_PORT
            portal = {'address': host, 'port': port}
            self.san_portals.append(portal)
            self.san_host = host
            self.san_port = port
        items = self.configuration.nexenta_iscsi_target_portals
        for item in items:
            if not item:
                continue
            hostport = item.split(':')
            host = hostport[0]
            port = DEFAULT_ISCSI_PORT
            if len(hostport) == 2:
                try:
                    port = int(hostport[1])
                except (TypeError, ValueError) as error:
                    LOG.error('Invalid port of %(storage_protocol)s '
                              'portal for backend %(backend_name)s '
                              'on host %(host)s: %(error)s',
                              {'storage_protocol': self.storage_protocol,
                               'backend_name': self.backend_name,
                               'host': self.host, 'error': error})
                    raise
            portal = {'address': host, 'port': port}
            if portal not in self.san_portals:
                self.san_portals.append(portal)
            if not self.san_host:
                self.san_host = host
            if not self.san_port:
                self.san_port = port
        if not self.san_portals:
            code = 'ENODATA'
            message = (_('%(product_name)s %(storage_protocol)s '
                         'host is not defined on host %(host)s, '
                         'please check the Cinder configuration '
                         'file for backend %(backend_name)s and '
                         'nexenta_iscsi_target_portals and/or '
                         'nexenta_host configuration options')
                       % {'product_name': self.product_name,
                          'storage_protocol': self.storage_protocol,
                          'host': self.host,
                          'backend_name': self.backend_name})
            raise jsonrpc.NefException(code=code, message=message)
        retries = 0
        while not self._check_for_setup_error():
            retries += 1
            self.nef.delay(retries)

    def _check_for_setup_error(self):
        """Check root volume group and iSCSI target service."""
        payload = {'fields': 'path'}
        try:
            self.nef.filesystems.get(self.san_pool, payload)
        except jsonrpc.NefException as error:
            LOG.error('Failed to get stat of SAN pool %(san_pool)s: %(error)s',
                      {'san_pool': self.san_pool, 'error': error})
            return False
        items = self.nef.volumegroups.properties
        names = [item['api'] for item in items if 'api' in item]
        fields = ','.join(names)
        payload = {'fields': fields}
        try:
            self.san_stat = self.nef.volumegroups.get(self.san_path, payload)
        except jsonrpc.NefException as error:
            LOG.error('Failed to get stat of SAN path %(san_path)s: %(error)s',
                      {'san_path': self.san_path, 'error': error})
            if error.code == 'ENOENT':
                self._create_san_path()
            return False
        if not self.san_stat:
            return False
        payload = {'fields': 'state'}
        try:
            service = self.nef.services.get('iscsit')
        except jsonrpc.NefException as error:
            LOG.error('Failed to get state of iSCSI target service: %(error)s',
                      {'error': error})
            return False
        if service['state'] != 'online':
            LOG.error('iSCSI target service is not online: %(state)s',
                      {'state': service['state']})
            return False
        return True

    def _create_san_path(self):
        payload = {
            'path': self.san_path,
            'volumeBlockSize': self.block_size
        }
        try:
            self.nef.volumegroups.create(payload)
        except jsonrpc.NefException as error:
            LOG.error('Failed to create SAN path %(san_path)s: %(error)s',
                      {'san_path': self.san_path, 'error': error})

    def _update_volume_props(self, volume, volume_type=None):
        """Updates the existing volume properties.

        :param volume: volume reference
        :param volume_type: new volume type
        """
        volume_path = self._get_volume_path(volume)
        volume_size = volume['size'] * units.Gi
        items = self.nef.volumes.properties
        names = [item['api'] for item in items if 'api' in item]
        # Workaround for NEX-21595
        names += ['source', 'volumeSize', 'referencedReservationSize']
        fields = ','.join(names)
        payload = {'fields': fields, 'source': True}
        props = self.nef.volumes.get(volume_path, payload)
        src = props['source']
        specs = self._get_volume_specs(volume, volume_type)
        payload = {}
        for item in items:
            if 'api' not in item:
                continue
            api = item['api']
            if api in specs:
                value = specs[api]
                if props[api] == value:
                    continue
                if 'change' in item:
                    code = 'EINVAL'
                    message = (_('Unable to change property %(name)s '
                                 'for volume %(volume)s. %(reason)s')
                               % {'name': item['name'],
                                  'volume': volume['name'],
                                  'reason': item['change']})
                    raise jsonrpc.NefException(code=code, message=message)
                payload[api] = value
            elif src[api] in ['local', 'received']:
                if props[api] == item['default']:
                    continue
                if 'inherit' in item:
                    LOG.debug('Unable to inherit property %(name)s '
                              'for volume %(volume)s. %(reason)s',
                              {'name': item['name'],
                               'volume': volume['name'],
                               'reason': item['inherit']})
                    continue
                payload[api] = None
        if props['volumeSize'] < volume_size:
            payload['volumeSize'] = volume_size
            if 0 < props['referencedReservationSize'] <= props['volumeSize']:
                payload['referencedReservationSize'] = volume_size
        if 'sparseVolume' in payload:
            sparse_volume = payload.pop('sparseVolume')
            if sparse_volume:
                payload['referencedReservationSize'] = 0
            else:
                payload['referencedReservationSize'] = volume_size
        if payload:
            self.nef.volumes.set(volume_path, payload)
        payload = {
            'volume': volume_path,
            'fields': 'guid'
        }
        logicalunits = self.nef.logicalunits.list(payload)
        payload = self._get_lu_specs(volume)
        for logicalunit in logicalunits:
            guid = logicalunit['guid']
            self.nef.logicalunits.set(guid, payload)

    def create_volume(self, volume):
        """Create a zfs volume on appliance.

        :param volume: volume reference
        :returns: model update dict for volume reference
        """
        volume_path = self._get_volume_path(volume)
        volume_size = volume['size'] * units.Gi
        payload = self._get_volume_specs(volume)
        payload['path'] = volume_path
        payload['volumeSize'] = volume_size
        self.nef.volumes.create(payload)

    @coordination.synchronized('{self.nef.lock}-{cache_name}')
    def _delete_cache(self, cache_name, cache_path, snapshot_path):
        """Delete a image cache.

        :param cache_name: cache volume name
        :param cache_path: cache volume path
        :param snapshot_path: cache snapshot path
        """
        payload = {'fields': 'clones'}
        try:
            props = self.nef.snapshots.get(snapshot_path, payload)
        except jsonrpc.NefException as error:
            LOG.error('Failed to get clones of image cache '
                      '%(name)s: %(error)s',
                      {'name': cache_name, 'error': error})
            return
        if props['clones']:
            clones = props['clones']
            count = len(clones)
            LOG.debug('Image cache %(name)s is still in use, '
                      '%(count)s clone(s) was found: %(clones)s',
                      {'name': cache_name, 'count': count,
                       'clones': clones})
            return
        payload = {'snapshots': True}
        try:
            self.nef.volumes.delete(cache_path, payload)
        except jsonrpc.NefException as error:
            LOG.error('Failed to delete image cache %(name)s: %(error)s',
                      {'name': cache_name, 'error': error})

    def _verify_cache(self, cache, snapshot):
        cache_path = self._get_volume_path(cache)
        payload = {'fields': 'volumeSize'}
        try:
            props = self.nef.volumes.get(cache_path, payload)
        except jsonrpc.NefException as error:
            if error.code == 'ENOENT':
                return cache, snapshot
            raise
        cache_size = props['volumeSize']
        cache['size'] = utils.roundgb(cache_size)
        snapshot_path = self._get_snapshot_path(snapshot)
        payload = {'fields': 'path'}
        try:
            self.nef.snapshots.get(snapshot_path, payload)
        except jsonrpc.NefException as error:
            if error.code == 'ENOENT':
                return cache, snapshot
            raise
        snapshot['volume_size'] = cache['size']
        return cache, snapshot

    @coordination.synchronized('{self.nef.lock}-{cache[name]}')
    def _create_cache(self, ctxt, cache, image_id, image_service):
        snapshot = {
            'id': cache['id'],
            'name': self.cache_snapshot_template % cache['id'],
            'volume_id': cache['id'],
            'volume_name': cache['name']
        }
        cache, snapshot = self._verify_cache(cache, snapshot)
        if snapshot.get('volume_size', 0) > 0:
            return snapshot
        if 'size' in cache:
            cache_path = self._get_volume_path(cache)
            new_uuid = six.text_type(uuid.uuid4())
            new_name = self.cache_image_template % new_uuid
            new_cache = {'name': new_name}
            new_path = self._get_volume_path(new_cache)
            payload = {'newPath': new_path}
            self.nef.volumes.rename(cache_path, payload)
        with image_utils.TemporaryImages.fetch(
                image_service, ctxt, image_id) as image_file:
            image_info = image_utils.qemu_img_info(image_file)
            image_size = image_info.virtual_size
            cache['size'] = utils.roundgb(image_size)
            self.create_volume(cache)
            self.copy_image_to_volume(ctxt, cache, image_service, image_id)
        snapshot['volume_size'] = cache['size']
        self.create_snapshot(snapshot)
        return snapshot

    def clone_image(self, ctxt, volume, image_location, image_meta,
                    image_service):
        """Create a volume efficiently from an existing image.

        image_location is a string whose format depends on the
        image service backend in use. The driver should use it
        to determine whether cloning is possible.

        image_meta is a dictionary that includes 'disk_format' (e.g.
        raw, qcow2) and other image attributes that allow drivers to
        decide whether they can clone the image without first requiring
        conversion.

        image_service is the reference of the image_service to use.
        Note that this is needed to be passed here for drivers that
        will want to fetch images from the image service directly.

        Returns a dict of volume properties eg. provider_location,
        boolean indicating whether cloning occurred.
        """
        if not self.image_cache:
            return None, False
        specs = self._get_volume_specs(volume)
        image_id = image_meta['id']
        image_checksum = image_meta['checksum']
        image_blocksize = specs['volumeBlockSize']
        compound = '%(id)s:%(checksum)s:%(blocksize)s' % {
            'id': image_id,
            'checksum': image_checksum,
            'blocksize': image_blocksize
        }
        namespace = uuid.UUID(image_id, version=4)
        name = utils.native_string(compound)
        cache_uuid = uuid.uuid5(namespace, name)
        cache_id = six.text_type(cache_uuid)
        cache_name = self.cache_image_template % cache_id
        cache_type_id = volume['volume_type_id']
        cache = {
            'id': cache_id,
            'name': cache_name,
            'volume_type_id': cache_type_id
        }
        try:
            snapshot = self._create_cache(ctxt, cache,
                                          image_id,
                                          image_service)
        except Exception as error:
            LOG.error('Failed to create cache %(cache)s '
                      'for image %(image)s: %(error)s',
                      {'cache': cache_name,
                       'image': image_id,
                       'error': error})
            return None, False
        if snapshot['volume_size'] > volume['size']:
            code = 'ENOSPC'
            message = (_('Unable to clone cache %(cache)s for '
                         'image %(image)s to volume %(volume)s: '
                         'cache size %(cache_size)sGB is larger '
                         'than volume size %(volume_size)sGB')
                       % {'cache': cache_name, 'image': image_id,
                          'volume': volume['name'],
                          'cache_size': snapshot['volume_size'],
                          'volume_size': volume['size']})
            raise jsonrpc.NefException(code=code, message=message)
        try:
            self.create_volume_from_snapshot(volume, snapshot)
        except Exception as error:
            LOG.error('Failed to clone cache %(cache)s for image '
                      '%(image)s to volume %(volume)s: %(error)s',
                      {'cache': cache['name'], 'image': image_id,
                       'volume': volume['name'], 'error': error})
            return None, False
        return None, True

    def _demote_volume(self, volume, volume_origin):
        """Demote a volume.

        :param volume: volume reference
        :param volume_origin: volume origin path
        """
        volume_path = self._get_volume_path(volume)
        payload = {'parent': volume_path, 'fields': 'path'}
        try:
            snapshots = self.nef.snapshots.list(payload)
        except jsonrpc.NefException as error:
            if error.code == 'ENOENT':
                return volume_origin
            raise
        origin_txg = 0
        origin_path = None
        clone_path = None
        for snapshot in snapshots:
            snapshot_path = snapshot['path']
            payload = {'fields': 'clones,creationTxg'}
            try:
                props = self.nef.snapshots.get(snapshot_path, payload)
            except jsonrpc.NefException as error:
                if error.code == 'ENOENT':
                    continue
                raise
            snapshot_clones = props['clones']
            # Workaround for NEX-22763
            snapshot_txg = int(props['creationTxg'])
            if snapshot_clones and snapshot_txg > origin_txg:
                clone_path = snapshot_clones[0]
                origin_txg = snapshot_txg
                origin_path = snapshot_path
        if clone_path:
            try:
                self.nef.volumes.promote(clone_path)
            except jsonrpc.NefException as error:
                if error.code in ['ENOENT', 'EBADARG']:
                    return volume_origin
                raise
            return origin_path
        return volume_origin

    def delete_volume(self, volume):
        """Deletes a volume.

        :param volume: volume reference
        """
        volume_path = self._get_volume_path(volume)
        payload = {'fields': 'originalSnapshot'}
        try:
            props = self.nef.volumes.get(volume_path, payload)
        except jsonrpc.NefException as error:
            if error.code == 'ENOENT':
                return
            raise
        volume_exist = True
        origin = props['originalSnapshot']
        payload = {'snapshots': True}
        while volume_exist:
            try:
                self.nef.volumes.delete(volume_path, payload)
            except jsonrpc.NefException as error:
                if error.code == 'EEXIST':
                    origin = self._demote_volume(volume, origin)
                    continue
                raise
            volume_exist = False
        if not origin:
            return
        origin_path, snapshot_name = origin.split('@')
        origin_name = posixpath.basename(origin_path)
        templates = {
            self.cache_snapshot_template: snapshot_name,
            self.cache_image_template: origin_name
        }
        for item, name in templates.items():
            if not utils.match_template(item, name):
                return
        self._delete_cache(origin_name, origin_path, origin)

    def extend_volume(self, volume, new_size):
        """Extend an existing volume.

        :param volume: volume reference
        :param new_size: volume new size in GB
        """
        volume_path = self._get_volume_path(volume)
        volume_size = new_size * units.Gi
        payload = {'fields': 'referencedReservationSize,volumeSize'}
        props = self.nef.volumes.get(volume_path, payload)
        payload = {'volumeSize': volume_size}
        if props['referencedReservationSize'] == props['volumeSize']:
            payload['referencedReservationSize'] = volume_size
        self.nef.volumes.set(volume_path, payload)

    def create_snapshot(self, snapshot):
        """Creates a snapshot.

        :param snapshot: snapshot reference
        """
        snapshot_path = self._get_snapshot_path(snapshot)
        payload = {'path': snapshot_path}
        self.nef.snapshots.create(payload)

    def delete_snapshot(self, snapshot):
        """Deletes a snapshot.

        :param snapshot: snapshot reference
        """
        snapshot_path = self._get_snapshot_path(snapshot)
        payload = {'defer': True}
        self.nef.snapshots.delete(snapshot_path, payload)

    def create_volume_from_snapshot(self, volume, snapshot):
        """Create new volume from other's snapshot on appliance.

        :param volume: reference of volume to be created
        :param snapshot: reference of source snapshot
        """
        volume_path = self._get_volume_path(volume)
        snapshot_path = self._get_snapshot_path(snapshot)
        payload = {'targetPath': volume_path}
        self.nef.snapshots.clone(snapshot_path, payload)
        self._update_volume_props(volume)

    def create_cloned_volume(self, volume, src_vref):
        """Creates a clone of the specified volume.

        :param volume: new volume reference
        :param src_vref: source volume reference
        """
        snapshot = {
            'name': self.origin_snapshot_template % volume['id'],
            'volume_id': src_vref['id'],
            'volume_name': src_vref['name'],
            'volume_size': src_vref['size']
        }
        self.create_snapshot(snapshot)
        try:
            self.create_volume_from_snapshot(volume, snapshot)
        finally:
            self.delete_snapshot(snapshot)

    def create_export(self, ctxt, volume, connector):
        """Driver entry point to get the export info for a new volume."""
        pass

    def ensure_export(self, ctxt, volume):
        """Driver entry point to get the export info for an existing volume."""
        pass

    def remove_export(self, ctxt, volume):
        """Driver entry point to remove an export for a volume."""
        pass

    def terminate_connection(self, volume, connector, **kwargs):
        """Terminate a connection to a volume.

        :param volume: a volume object
        :param connector: a connector object
        :returns: dictionary of connection information
        """
        info = {'driver_volume_type': self.driver_volume_type, 'data': {}}
        initiator = None
        host_groups = []
        volume_path = self._get_volume_path(volume)
        if isinstance(connector, dict) and 'initiator' in connector:
            connectors = self._get_volume_connectors(volume)
            if connectors.count(connector) > 1:
                LOG.info('Detected %(count)s connections from host '
                         '%(host_name)s (IP:%(host_ip)s) to volume '
                         '%(volume)s, skip terminating connection',
                         {'count': connectors.count(connector),
                          'host_name': connector.get('host', 'unknown'),
                          'host_ip': connector.get('ip', 'unknown'),
                          'volume': volume['name']})
                return True
            initiator = connector['initiator']
            host_groups.append(DEFAULT_HOST_GROUP)
            host_group = self._get_hostgroup(initiator)
            if host_group is not None:
                host_groups.append(host_group)
            LOG.debug('Terminate connection for volume %(volume)s '
                      'and initiator %(initiator)s',
                      {'volume': volume['name'],
                       'initiator': initiator})
        else:
            LOG.debug('Terminate all connections for volume %(volume)s',
                      {'volume': volume['name']})

        payload = {'volume': volume_path}
        mappings = self.nef.mappings.list(payload)
        if not mappings:
            LOG.debug('There are no LUN mappings found for volume %(volume)s',
                      {'volume': volume['name']})
            return info
        for mapping in mappings:
            mapping_id = mapping.get('id')
            mapping_tg = mapping.get('targetGroup')
            mapping_hg = mapping.get('hostGroup')
            if initiator is None or mapping_hg in host_groups:
                LOG.debug('Delete LUN mapping %(id)s for volume %(volume)s, '
                          'target group %(tg)s and host group %(hg)s',
                          {'id': mapping_id, 'volume': volume['name'],
                           'tg': mapping_tg, 'hg': mapping_hg})
                self.nef.mappings.delete(mapping_id)
            else:
                LOG.debug('Skip LUN mapping %(id)s for volume %(volume)s, '
                          'target group %(tg)s and host group %(hg)s',
                          {'id': mapping_id, 'volume': volume['name'],
                           'tg': mapping_tg, 'hg': mapping_hg})
        return info

    def get_volume_stats(self, refresh=False):
        """Get volume stats.

        If 'refresh' is True, run update the stats first.
        """
        if refresh or not self._stats:
            self._update_volume_stats()
        return self._stats

    def _update_volume_stats(self):
        """Retrieve stats info for NexentaStor appliance."""
        provisioned_capacity_gb = total_volumes = total_snapshots = 0
        volumes = objects.VolumeList.get_all_by_host(self.ctxt, self.host)
        for volume in volumes:
            provisioned_capacity_gb += volume['size']
            total_volumes += 1
        snapshots = objects.SnapshotList.get_by_host(self.ctxt, self.host)
        for snapshot in snapshots:
            provisioned_capacity_gb += snapshot['volume_size']
            total_snapshots += 1
        description = (
            self.configuration.safe_get('nexenta_dataset_description'))
        if not description:
            description = '%(product)s %(host)s:%(path)s' % {
                'product': self.product_name,
                'host': self.san_host,
                'path': self.san_path
            }
        max_over_subscription_ratio = (
            self.configuration.safe_get('max_over_subscription_ratio'))
        reserved_percentage = (
            self.configuration.safe_get('reserved_percentage'))
        if reserved_percentage is None:
            reserved_percentage = 0
        location_info = '%(driver)s:%(host)s:%(path)s' % {
            'driver': self.san_driver,
            'host': self.san_host,
            'path': self.san_path
        }
        display_name = 'Capabilities of %(product)s %(protocol)s driver' % {
            'product': self.product_name,
            'protocol': self.storage_protocol
        }
        stats = {
            'backend_state': 'down',
            'driver_version': self.VERSION,
            'vendor_name': self.vendor_name,
            'storage_protocol': self.storage_protocol,
            'volume_backend_name': self.backend_name,
            'location_info': location_info,
            'description': description,
            'display_name': display_name,
            'pool_name': self.san_pool,
            'multiattach': True,
            'QoS_support': False,
            'consistencygroup_support': True,
            'consistent_group_snapshot_enabled': True,
            'online_extend_support': True,
            'sparse_copy_volume': True,
            'thin_provisioning_support': True,
            'thick_provisioning_support': True,
            'total_capacity_gb': 'unknown',
            'allocated_capacity_gb': 'unknown',
            'free_capacity_gb': 'unknown',
            'provisioned_capacity_gb': provisioned_capacity_gb,
            'total_volumes': total_volumes,
            'total_snapshots': total_snapshots,
            'max_over_subscription_ratio': max_over_subscription_ratio,
            'reserved_percentage': reserved_percentage,
            'nef_scheme': self.nef.scheme,
            'nef_hosts': ','.join(self.nef.hosts),
            'nef_port': self.nef.port,
            'nef_url': self.nef.url()
        }
        payload = {'fields': 'bytesAvailable,bytesUsed'}
        try:
            san_stat = self.nef.volumegroups.get(self.san_path, payload)
        except jsonrpc.NefException as error:
            LOG.error('Failed to get backend statistics for host %(host)s '
                      'and volume backend %(backend_name)s: %(error)s',
                      {'host': self.host,
                       'backend_name': self.backend_name,
                       'error': error})
        else:
            available = san_stat['bytesAvailable'] // units.Gi
            used = san_stat['bytesUsed'] // units.Gi
            stats['free_capacity_gb'] = available
            stats['allocated_capacity_gb'] = used
            stats['total_capacity_gb'] = available + used
            stats['backend_state'] = 'up'
        self._stats = stats
        LOG.debug('Updated volume backend statistics for host %(host)s '
                  'and volume backend %(backend_name)s: %(stats)s',
                  {'host': self.host,
                   'backend_name': self.backend_name,
                   'stats': self._stats})

    def _get_volume_connectors(self, volume):
        """Return list of the volume connectors."""
        connectors = []
        if 'volume_attachment' not in volume:
            return connectors
        volume_attachments = volume['volume_attachment']
        if not isinstance(volume_attachments, list):
            return connectors
        for volume_attachment in volume_attachments:
            if not isinstance(volume_attachment, dict):
                continue
            if 'connector' not in volume_attachment:
                continue
            connector = volume_attachment['connector']
            connectors.append(connector)
        return connectors

    def _get_volume_path(self, volume):
        """Return ZFS datset path for the volume."""
        volume_name = volume['name']
        volume_path = posixpath.join(self.san_path, volume_name)
        return volume_path

    def _get_snapshot_path(self, snapshot):
        """Return ZFS snapshot path for the snapshot."""
        volume_name = snapshot['volume_name']
        snapshot_name = snapshot['name']
        volume_path = posixpath.join(self.san_path, volume_name)
        snapshot_path = '%(volume_path)s@%(snapshot_name)s' % {
            'volume_path': volume_path,
            'snapshot_name': snapshot_name
        }
        return snapshot_path

    def _get_addrs(self):
        """Returns NexentaStor IP addresses list."""
        addrs = []
        payload = {'fields': 'address,state'}
        items = self.nef.netaddrs.list(payload)
        for item in items:
            if item['state'] != 'ok':
                continue
            ip_mask = six.text_type(item['address'])
            ip = ip_mask.split('/')[0]
            addr = ipaddress.ip_address(ip)
            if not addr.is_loopback:
                addrs.append(addr.exploded)
        LOG.debug('Configured IP addresses: %(addrs)s',
                  {'addrs': addrs})
        return addrs

    def _get_portals(self, addrs):
        """Return configured iSCSI portals list."""
        portals = []
        items = self.san_portals
        for item in items:
            if item['address'] in addrs:
                portals.append(item)
        return portals

    def _get_targets(self, hosts):
        """Return configured iSCSI targets dictionary."""
        targets = {}
        payload = {'fields': 'name,state,portals'}
        items = self.nef.targets.list(payload)
        for item in items:
            name = item['name']
            state = item['state']
            portals = item['portals']
            if state != 'online':
                LOG.debug('Skip iSCSI target %(name)s: %(state)s',
                          {'name': name, 'state': state})
                continue
            if not name.startswith(self.target_prefix):
                LOG.debug('Skip iSCSI target %(name)s: target name '
                          'do not match configured prefix %(prefix)s',
                          {'name': name, 'prefix': self.target_prefix})
                continue
            if not portals:
                LOG.debug('Skip iSCSI target %(name)s: no target portals',
                          {'name': name})
                continue
            if not all(portal in hosts for portal in portals):
                LOG.debug('Skip iSCSI target %(name)s: target portals '
                          '%(portals)s do not match host portals %(hosts)s',
                          {'name': name, 'portals': portals, 'hosts': hosts})
                continue
            targets[name] = utils.prt2tpg(portals)
        return targets

    def _get_targetgroups(self, targets):
        """Return configured target groups dictionary."""
        dist = {}
        payload = {'fields': 'name,members'}
        items = self.nef.targetgroups.list(payload)
        for item in items:
            name = item['name']
            members = item['members']
            if not name.startswith(self.targetgroup_prefix):
                LOG.debug('Skip targetgroup %(name)s: group name '
                          'do not match configured prefix %(prefix)s',
                          {'name': name, 'prefix': self.targetgroup_prefix})
                continue
            if not members:
                LOG.debug('Skip targetgroup %(name)s: no members found',
                          {'name': name})
                continue
            if not all(member in targets for member in members):
                LOG.debug('Skip targetgroup %(name)s: group members '
                          '%(members)s do not match host targets %(targets)s',
                          {'name': name, 'members': members,
                           'targets': targets})
                continue
            member = members[0]
            portals = targets[member]
            dist[name] = {'iqn': member, 'portals': portals}
        return dist

    def initialize_connection(self, volume, connector):
        """Do all steps to get zfs volume exported at separate target.

        :param volume: volume reference
        :param connector: connector reference
        :returns: dictionary of connection information
        """
        initiator = connector.get('initiator', None)
        multipath = connector.get('multipath', False)
        LOG.debug('Initialize connection for volume %(volume)s and '
                  'initiator %(initiator)s, multipath: %(multipath)s',
                  {'volume': volume['name'], 'initiator': initiator,
                   'multipath': multipath})
        hostgroup = DEFAULT_HOST_GROUP
        if initiator:
            hostgroup = self._get_hostgroup(initiator)
            if not hostgroup:
                hostgroup = self._create_hostgroup(initiator)
        addrs = self._get_addrs()
        portals = self._get_portals(addrs)
        targets = self._get_targets(portals)
        dist = self._get_targetgroups(targets)
        stat = {}
        volume_path = self._get_volume_path(volume)
        payload = {
            'fields': 'id,lun,hostGroup,targetGroup,volume'
        }
        mappings = self.nef.mappings.list(payload)
        for mapping in mappings:
            uid = mapping['id']
            lun = mapping['lun']
            targetgroup = mapping['targetGroup']
            if targetgroup == DEFAULT_TARGET_GROUP:
                self.nef.mappings.delete(uid)
                continue
            if targetgroup not in dist:
                continue
            if targetgroup not in stat:
                stat[targetgroup] = 0
            stat[targetgroup] += 1
            if mapping['hostGroup'] != hostgroup:
                continue
            if mapping['volume'] != volume_path:
                continue
            target = dist[targetgroup]
            return self._get_connection_info(volume, multipath, target, lun)
        targetgroup = None
        if stat:
            key = min(stat, key=stat.get)
            if stat[key] < self.luns_per_target:
                targetgroup = key
                target = dist[targetgroup]
        if not targetgroup and dist:
            targetgroup = random.choice(list(dist))
            target = dist[targetgroup]
        if not targetgroup:
            suffix = uuid.uuid4().hex
            iqn = self._create_target(suffix, portals)
            targetgroup = self._create_targetgroup(suffix, iqn)
            target = {
                'iqn': iqn,
                'portals': utils.prt2tpg(portals)
            }
        payload = {
            'volume': volume_path,
            'targetGroup': targetgroup,
            'hostGroup': hostgroup
        }
        uid = self.nef.mappings.create(payload)
        payload = {'fields': 'lun'}
        for attempt in range(1, self.nef.retries + 1):
            try:
                mapping = self.nef.mappings.get(uid, payload)
            except jsonrpc.NefException:
                if attempt == self.nef.retries:
                    raise
                self.nef.delay(attempt)
            else:
                lun = mapping['lun']
                break
        payload = {'volume': volume_path, 'fields': 'guid'}
        logicalunits = self.nef.logicalunits.list(payload)
        if not logicalunits:
            code = 'ENODATA'
            message = (_('Unable to find logical unit for volume %(volume)s')
                       % {'volume': volume['name']})
            raise jsonrpc.NefException(code=code, message=message)
        logicalunit = logicalunits[0]
        guid = logicalunit['guid']
        payload = self._get_lu_specs(volume)
        self.nef.logicalunits.set(guid, payload)
        return self._get_connection_info(volume, multipath, target, lun)

    def _get_connection_info(self, volume, multipath, target, lun):
        data = {
            'encrypted': False,
            'discard': True,
            'target_discovered': False,
            'volume_id': volume['id']
        }
        portals = target['portals']
        iqn = target['iqn']
        count = len(portals)
        index = random.randrange(count)
        data.update({
            'target_lun': lun,
            'target_iqn': iqn,
            'target_portal': portals[index]
        })
        if multipath:
            data.update({
                'target_luns': [lun] * count,
                'target_iqns': [iqn] * count,
                'target_portals': portals
            })
        return {
            'driver_volume_type': self.driver_volume_type,
            'data': data
        }

    def _create_target(self, suffix, portals):
        """Create a new target with portals.

        :param suffix: target name suffix
        :param portals: target portals list
        """
        name = '%(prefix)s-%(suffix)s' % {
            'prefix': self.target_prefix,
            'suffix': suffix
        }
        payload = {'name': name, 'portals': portals}
        return self.nef.targets.create(payload)

    def _create_targetgroup(self, suffix, target):
        """Create a new target group with target.

        :param suffix: group name siffix
        :param target: group member
        """
        name = '%(prefix)s-%(suffix)s' % {
            'prefix': self.targetgroup_prefix,
            'suffix': suffix
        }
        members = [target]
        payload = {'name': name, 'members': members}
        return self.nef.targetgroups.create(payload)

    def _get_hostgroup(self, member):
        """Find existing hostgroup by group member.

        :param member: hostgroup member
        :returns: hostgroup name
        """
        payload = {'fields': 'members,name'}
        hostgroups = self.nef.hostgroups.list(payload)
        for hostgroup in hostgroups:
            members = hostgroup['members']
            if member in members:
                name = hostgroup['name']
                LOG.debug('Found hostgroup %(name)s by member %(member)s',
                          {'name': name, 'member': member})
                return name
        return None

    def _create_hostgroup(self, member):
        """Create a new host group.

        :param member: hostgroup member
        :returns: hostgroup name
        """
        name = '%(prefix)s-%(suffix)s' % {
            'prefix': self.host_group_prefix,
            'suffix': uuid.uuid4().hex
        }
        members = [member]
        payload = {'name': name, 'members': members}
        self.nef.hostgroups.create(payload)
        return name

    def create_consistencygroup(self, ctxt, group):
        """Creates a consistency group.

        :param ctxt: the context of the caller.
        :param group: the dictionary of the consistency group to be created.
        :returns: group_model_update
        """
        group_model_update = {}
        return group_model_update

    def create_group(self, ctxt, group):
        """Creates a group.

        :param ctxt: the context of the caller.
        :param group: the group object.
        :returns: model_update
        """
        return self.create_consistencygroup(ctxt, group)

    def delete_consistencygroup(self, ctxt, group, volumes):
        """Deletes a consistency group.

        :param ctxt: the context of the caller.
        :param group: the dictionary of the consistency group to be deleted.
        :param volumes: a list of volume dictionaries in the group.
        :returns: group_model_update, volumes_model_update
        """
        group_model_update = {}
        volumes_model_update = []
        for volume in volumes:
            self.delete_volume(volume)
        return group_model_update, volumes_model_update

    def delete_group(self, ctxt, group, volumes):
        """Deletes a group.

        :param ctxt: the context of the caller.
        :param group: the group object.
        :param volumes: a list of volume objects in the group.
        :returns: model_update, volumes_model_update
        """
        return self.delete_consistencygroup(ctxt, group, volumes)

    def update_consistencygroup(self, ctxt, group, add_volumes=None,
                                remove_volumes=None):
        """Updates a consistency group.

        :param ctxt: the context of the caller.
        :param group: the dictionary of the consistency group to be updated.
        :param add_volumes: a list of volume dictionaries to be added.
        :param remove_volumes: a list of volume dictionaries to be removed.
        :returns: group_model_update, add_volumes_update, remove_volumes_update
        """
        group_model_update = {}
        add_volumes_update = []
        remove_volumes_update = []
        return group_model_update, add_volumes_update, remove_volumes_update

    def update_group(self, ctxt, group,
                     add_volumes=None, remove_volumes=None):
        """Updates a group.

        :param ctxt: the context of the caller.
        :param group: the group object.
        :param add_volumes: a list of volume objects to be added.
        :param remove_volumes: a list of volume objects to be removed.
        :returns: model_update, add_volumes_update, remove_volumes_update
        """
        return self.update_consistencygroup(ctxt, group, add_volumes,
                                            remove_volumes)

    def create_cgsnapshot(self, ctxt, cgsnapshot, snapshots):
        """Creates a consistency group snapshot.

        :param ctxt: the context of the caller.
        :param cgsnapshot: the dictionary of the cgsnapshot to be created.
        :param snapshots: a list of snapshot dictionaries in the cgsnapshot.
        :returns: group_model_update, snapshots_model_update
        """
        group_model_update = {}
        snapshots_model_update = []
        cgsnapshot_name = self.group_snapshot_template % cgsnapshot['id']
        cgsnapshot_path = '%s@%s' % (self.san_path, cgsnapshot_name)
        create_payload = {'path': cgsnapshot_path, 'recursive': True}
        self.nef.snapshots.create(create_payload)
        for snapshot in snapshots:
            volume_name = snapshot['volume_name']
            volume_path = posixpath.join(self.san_path, volume_name)
            snapshot_name = snapshot['name']
            snapshot_path = '%s@%s' % (volume_path, cgsnapshot_name)
            rename_payload = {'newName': snapshot_name}
            self.nef.snapshots.rename(snapshot_path, rename_payload)
        delete_payload = {'defer': True, 'recursive': True}
        self.nef.snapshots.delete(cgsnapshot_path, delete_payload)
        return group_model_update, snapshots_model_update

    def create_group_snapshot(self, ctxt, group_snapshot, snapshots):
        """Creates a group_snapshot.

        :param ctxt: the context of the caller.
        :param group_snapshot: the GroupSnapshot object to be created.
        :param snapshots: a list of Snapshot objects in the group_snapshot.
        :returns: model_update, snapshots_model_update
        """
        return self.create_cgsnapshot(ctxt, group_snapshot, snapshots)

    def delete_cgsnapshot(self, ctxt, cgsnapshot, snapshots):
        """Deletes a consistency group snapshot.

        :param ctxt: the context of the caller.
        :param cgsnapshot: the dictionary of the cgsnapshot to be created.
        :param snapshots: a list of snapshot dictionaries in the cgsnapshot.
        :returns: group_model_update, snapshots_model_update
        """
        group_model_update = {}
        snapshots_model_update = []
        for snapshot in snapshots:
            self.delete_snapshot(snapshot)
        return group_model_update, snapshots_model_update

    def delete_group_snapshot(self, ctxt, group_snapshot, snapshots):
        """Deletes a group_snapshot.

        :param ctxt: the context of the caller.
        :param group_snapshot: the GroupSnapshot object to be deleted.
        :param snapshots: a list of snapshot objects in the group_snapshot.
        :returns: model_update, snapshots_model_update
        """
        return self.delete_cgsnapshot(ctxt, group_snapshot, snapshots)

    def create_consistencygroup_from_src(self, ctxt, group, volumes,
                                         cgsnapshot=None, snapshots=None,
                                         source_cg=None, source_vols=None):
        """Creates a consistency group from source.

        :param ctxt: the context of the caller.
        :param group: the dictionary of the consistency group to be created.
        :param volumes: a list of volume dictionaries in the group.
        :param cgsnapshot: the dictionary of the cgsnapshot as source.
        :param snapshots: a list of snapshot dictionaries in the cgsnapshot.
        :param source_cg: the dictionary of a consistency group as source.
        :param source_vols: a list of volume dictionaries in the source_cg.
        :returns: group_model_update, volumes_model_update
        """
        group_model_update = {}
        volumes_model_update = []
        if cgsnapshot and snapshots:
            for volume, snapshot in zip(volumes, snapshots):
                self.create_volume_from_snapshot(volume, snapshot)
        elif source_cg and source_vols:
            snapshot_name = self.origin_snapshot_template % group['id']
            snapshot_path = '%s@%s' % (self.san_path, snapshot_name)
            create_payload = {'path': snapshot_path, 'recursive': True}
            self.nef.snapshots.create(create_payload)
            for volume, source_vol in zip(volumes, source_vols):
                snapshot = {
                    'name': snapshot_name,
                    'volume_id': source_vol['id'],
                    'volume_name': source_vol['name'],
                    'volume_size': source_vol['size']
                }
                self.create_volume_from_snapshot(volume, snapshot)
            delete_payload = {'defer': True, 'recursive': True}
            self.nef.snapshots.delete(snapshot_path, delete_payload)
        return group_model_update, volumes_model_update

    def create_group_from_src(self, ctxt, group, volumes,
                              group_snapshot=None, snapshots=None,
                              source_group=None, source_vols=None):
        """Creates a group from source.

        :param ctxt: the context of the caller.
        :param group: the Group object to be created.
        :param volumes: a list of Volume objects in the group.
        :param group_snapshot: the GroupSnapshot object as source.
        :param snapshots: a list of snapshot objects in group_snapshot.
        :param source_group: the Group object as source.
        :param source_vols: a list of volume objects in the source_group.
        :returns: model_update, volumes_model_update
        """
        return self.create_consistencygroup_from_src(ctxt, group, volumes,
                                                     group_snapshot, snapshots,
                                                     source_group, source_vols)

    def _get_existing_volume(self, existing_ref):
        types = {
            'source-name': 'name',
            'source-guid': 'guid'
        }
        if not any(key in types for key in existing_ref):
            keys = ', '.join(types.keys())
            code = 'EINVAL'
            message = (_('Manage existing volume failed '
                         'due to invalid backend reference. '
                         'Volume reference must contain '
                         'at least one valid key: %(keys)s')
                       % {'keys': keys})
            raise jsonrpc.NefException(code=code, message=message)
        payload = {
            'parent': self.san_path,
            'fields': 'name,path,volumeSize'
        }
        for key, value in types.items():
            if key in existing_ref:
                payload[value] = existing_ref[key]
        existing_volumes = self.nef.volumes.list(payload)
        if len(existing_volumes) == 1:
            volume_path = existing_volumes[0]['path']
            volume_name = existing_volumes[0]['name']
            refsize = existing_volumes[0]['volumeSize']
            volume_size = utils.roundgb(refsize)
            existing_volume = {
                'name': volume_name,
                'path': volume_path,
                'size': volume_size
            }
            vid = volume_utils.extract_id_from_volume_name(volume_name)
            if volume_utils.check_already_managed_volume(vid):
                code = 'EEXIST'
                message = (_('Volume %(name)s already managed')
                           % {'name': volume_name})
                raise jsonrpc.NefException(code=code, message=message)
            return existing_volume
        elif not existing_volumes:
            code = 'ENOENT'
            reason = _('no matching volumes were found')
        else:
            code = 'EINVAL'
            reason = _('too many volumes were found')
        message = (_('Unable to manage existing volume by '
                     'reference %(reference)s: %(reason)s')
                   % {'reference': existing_ref, 'reason': reason})
        raise jsonrpc.NefException(code=code, message=message)

    def _check_already_managed_snapshot(self, snapshot_id):
        """Check cinder database for already managed snapshot.

        :param snapshot_id: snapshot id parameter
        :returns: return True, if database entry with specified
                  snapshot id exists, otherwise return False
        """
        if not isinstance(snapshot_id, six.string_types):
            return False
        try:
            uuid.UUID(snapshot_id, version=4)
        except ValueError:
            return False
        return objects.Snapshot.exists(self.ctxt, snapshot_id)

    def _get_existing_snapshot(self, snapshot, existing_ref):
        types = {
            'source-name': 'name',
            'source-guid': 'guid'
        }
        if not any(key in types for key in existing_ref):
            keys = ', '.join(types.keys())
            code = 'EINVAL'
            message = (_('Manage existing snapshot failed '
                         'due to invalid backend reference. '
                         'Snapshot reference must contain '
                         'at least one valid key: %(keys)s')
                       % {'keys': keys})
            raise jsonrpc.NefException(code=code, message=message)
        volume_name = snapshot['volume_name']
        volume_size = snapshot['volume_size']
        volume = {'name': volume_name}
        volume_path = self._get_volume_path(volume)
        payload = {
            'parent': volume_path,
            'fields': 'name,path',
            'recursive': False
        }
        for key, value in types.items():
            if key in existing_ref:
                payload[value] = existing_ref[key]
        existing_snapshots = self.nef.snapshots.list(payload)
        if len(existing_snapshots) == 1:
            name = existing_snapshots[0]['name']
            path = existing_snapshots[0]['path']
            existing_snapshot = {
                'name': name,
                'path': path,
                'volume_name': volume_name,
                'volume_size': volume_size
            }
            sid = volume_utils.extract_id_from_snapshot_name(name)
            if self._check_already_managed_snapshot(sid):
                code = 'EEXIST'
                message = (_('Snapshot %(name)s already managed')
                           % {'name': name})
                raise jsonrpc.NefException(code=code, message=message)
            return existing_snapshot
        elif not existing_snapshots:
            code = 'ENOENT'
            reason = _('no matching snapshots were found')
        else:
            code = 'EINVAL'
            reason = _('too many snapshots were found')
        message = (_('Unable to manage existing snapshot by '
                     'reference %(reference)s: %(reason)s')
                   % {'reference': existing_ref, 'reason': reason})
        raise jsonrpc.NefException(code=code, message=message)

    def manage_existing(self, volume, existing_ref):
        """Brings an existing backend storage object under Cinder management.

        existing_ref is passed straight through from the API request's
        manage_existing_ref value, and it is up to the driver how this should
        be interpreted.  It should be sufficient to identify a storage object
        that the driver should somehow associate with the newly-created cinder
        volume structure.

        There are two ways to do this:

        1. Rename the backend storage object so that it matches the,
           volume['name'] which is how drivers traditionally map between a
           cinder volume and the associated backend storage object.

        2. Place some metadata on the volume, or somewhere in the backend, that
           allows other driver requests (e.g. delete, clone, attach, detach...)
           to locate the backend storage object when required.

        If the existing_ref doesn't make sense, or doesn't refer to an existing
        backend storage object, raise a ManageExistingInvalidReference
        exception.

        The volume may have a volume_type, and the driver can inspect that and
        compare against the properties of the referenced backend storage
        object.  If they are incompatible, raise a
        ManageExistingVolumeTypeMismatch, specifying a reason for the failure.

        :param volume:       Cinder volume to manage
        :param existing_ref: Driver-specific information used to identify a
                             volume
        """
        existing_volume = self._get_existing_volume(existing_ref)
        existing_volume_path = existing_volume['path']
        payload = {'volume': existing_volume_path}
        mappings = self.nef.mappings.list(payload)
        if mappings:
            code = 'EEXIST'
            message = (_('Unable to manage existing volume %(name)s '
                         'due to existing LUN mappings: %(mappings)s')
                       % {'name': existing_volume['name'],
                          'mappings': mappings})
            raise jsonrpc.NefException(code=code, message=message)
        if existing_volume['name'] != volume['name']:
            volume_path = self._get_volume_path(volume)
            payload = {'newPath': volume_path}
            self.nef.volumes.rename(existing_volume_path, payload)
        self._update_volume_props(volume)

    def manage_existing_get_size(self, volume, existing_ref):
        """Return size of volume to be managed by manage_existing.

        When calculating the size, round up to the next GB.

        :param volume:       Cinder volume to manage
        :param existing_ref: Driver-specific information used to identify a
                             volume
        :returns size:       Volume size in GiB (integer)
        """
        existing_volume = self._get_existing_volume(existing_ref)
        return existing_volume['size']

    def get_manageable_volumes(self, cinder_volumes, marker, limit, offset,
                               sort_keys, sort_dirs):
        """List volumes on the backend available for management by Cinder.

        Returns a list of dictionaries, each specifying a volume in the host,
        with the following keys:
        - reference (dictionary): The reference for a volume, which can be
          passed to "manage_existing".
        - size (int): The size of the volume according to the storage
          backend, rounded up to the nearest GB.
        - safe_to_manage (boolean): Whether or not this volume is safe to
          manage according to the storage backend. For example, is the volume
          in use or invalid for any reason.
        - reason_not_safe (string): If safe_to_manage is False, the reason why.
        - cinder_id (string): If already managed, provide the Cinder ID.
        - extra_info (string): Any extra information to return to the user

        :param cinder_volumes: A list of volumes in this host that Cinder
                               currently manages, used to determine if
                               a volume is manageable or not.
        :param marker:    The last item of the previous page; we return the
                          next results after this value (after sorting)
        :param limit:     Maximum number of items to return
        :param offset:    Number of items to skip after marker
        :param sort_keys: List of keys to sort results by (valid keys are
                          'identifier' and 'size')
        :param sort_dirs: List of directions to sort by, corresponding to
                          sort_keys (valid directions are 'asc' and 'desc')
        """
        manageable_volumes = []
        cinder_volume_names = {}
        for cinder_volume in cinder_volumes:
            key = cinder_volume['name']
            value = cinder_volume['id']
            cinder_volume_names[key] = value
        payload = {
            'parent': self.san_path,
            'fields': 'name,guid,path,volumeSize'
        }
        volumes = self.nef.volumes.list(payload)
        for volume in volumes:
            safe_to_manage = True
            reason_not_safe = None
            cinder_id = None
            extra_info = None
            path = volume['path']
            guid = volume['guid']
            refsize = volume['volumeSize']
            size = utils.roundgb(refsize)
            name = volume['name']
            if utils.match_template(self.cache_image_template, name):
                continue
            if name in cinder_volume_names:
                cinder_id = cinder_volume_names[name]
                safe_to_manage = False
                reason_not_safe = _('Volume already managed')
            else:
                payload = {
                    'volume': path,
                    'fields': 'hostGroup'
                }
                mappings = self.nef.mappings.list(payload)
                members = []
                for mapping in mappings:
                    hostgroup = mapping['hostGroup']
                    if hostgroup == DEFAULT_HOST_GROUP:
                        members.append(hostgroup)
                    else:
                        group = self.nef.hostgroups.get(hostgroup)
                        members += group['members']
                if members:
                    safe_to_manage = False
                    hosts = ', '.join(members)
                    reason_not_safe = (_('Volume is connected '
                                         'to host(s) %(hosts)s')
                                       % {'hosts': hosts})
            reference = {
                'source-name': name,
                'source-guid': guid
            }
            manageable_volumes.append({
                'reference': reference,
                'size': size,
                'safe_to_manage': safe_to_manage,
                'reason_not_safe': reason_not_safe,
                'cinder_id': cinder_id,
                'extra_info': extra_info
            })
        return volume_utils.paginate_entries_list(
            manageable_volumes, marker, limit,
            offset, sort_keys, sort_dirs)

    def unmanage(self, volume):
        """Removes the specified volume from Cinder management.

        Does not delete the underlying backend storage object.

        For most drivers, this will not need to do anything.  However, some
        drivers might use this call as an opportunity to clean up any
        Cinder-specific configuration that they have associated with the
        backend storage object.

        :param volume: Cinder volume to unmanage
        """
        pass

    def manage_existing_snapshot(self, snapshot, existing_ref):
        """Brings an existing backend storage object under Cinder management.

        existing_ref is passed straight through from the API request's
        manage_existing_ref value, and it is up to the driver how this should
        be interpreted.  It should be sufficient to identify a storage object
        that the driver should somehow associate with the newly-created cinder
        snapshot structure.

        There are two ways to do this:

        1. Rename the backend storage object so that it matches the
           snapshot['name'] which is how drivers traditionally map between a
           cinder snapshot and the associated backend storage object.

        2. Place some metadata on the snapshot, or somewhere in the backend,
           that allows other driver requests (e.g. delete) to locate the
           backend storage object when required.

        If the existing_ref doesn't make sense, or doesn't refer to an existing
        backend storage object, raise a ManageExistingInvalidReference
        exception.

        :param snapshot:     Cinder volume snapshot to manage
        :param existing_ref: Driver-specific information used to identify a
                             volume snapshot
        """
        existing_snapshot = self._get_existing_snapshot(snapshot, existing_ref)
        existing_snapshot_path = existing_snapshot['path']
        if existing_snapshot['name'] != snapshot['name']:
            payload = {'newName': snapshot['name']}
            self.nef.snapshots.rename(existing_snapshot_path, payload)

    def manage_existing_snapshot_get_size(self, snapshot, existing_ref):
        """Return size of snapshot to be managed by manage_existing.

        When calculating the size, round up to the next GB.

        :param snapshot:     Cinder volume snapshot to manage
        :param existing_ref: Driver-specific information used to identify a
                             volume snapshot
        :returns size:       Volume snapshot size in GiB (integer)
        """
        existing_snapshot = self._get_existing_snapshot(snapshot, existing_ref)
        return existing_snapshot['volume_size']

    def get_manageable_snapshots(self, cinder_snapshots, marker, limit, offset,
                                 sort_keys, sort_dirs):
        """List snapshots on the backend available for management by Cinder.

        Returns a list of dictionaries, each specifying a snapshot in the host,
        with the following keys:
        - reference (dictionary): The reference for a snapshot, which can be
          passed to "manage_existing_snapshot".
        - size (int): The size of the snapshot according to the storage
          backend, rounded up to the nearest GB.
        - safe_to_manage (boolean): Whether or not this snapshot is safe to
          manage according to the storage backend. For example, is the snapshot
          in use or invalid for any reason.
        - reason_not_safe (string): If safe_to_manage is False, the reason why.
        - cinder_id (string): If already managed, provide the Cinder ID.
        - extra_info (string): Any extra information to return to the user
        - source_reference (string): Similar to "reference", but for the
          snapshot's source volume.

        :param cinder_snapshots: A list of snapshots in this host that Cinder
                                 currently manages, used to determine if
                                 a snapshot is manageable or not.
        :param marker:    The last item of the previous page; we return the
                          next results after this value (after sorting)
        :param limit:     Maximum number of items to return
        :param offset:    Number of items to skip after marker
        :param sort_keys: List of keys to sort results by (valid keys are
                          'identifier' and 'size')
        :param sort_dirs: List of directions to sort by, corresponding to
                          sort_keys (valid directions are 'asc' and 'desc')

        """
        temporary_snapshots = {
            self.cache_snapshot_template: 'image cache',
            self.origin_snapshot_template: 'temporary origin',
            self.group_snapshot_template: 'temporary group'
        }
        service_snapshots = {
            'hprService': 'replication',
            'snaplistId': 'snapping'
        }
        manageable_snapshots = []
        cinder_volume_names = {}
        cinder_snapshot_names = {}
        cinder_volumes = objects.VolumeList.get_all_by_host(
            self.ctxt, self.host)
        for cinder_volume in cinder_volumes:
            key = self._get_volume_path(cinder_volume)
            value = {
                'name': cinder_volume['name'],
                'size': cinder_volume['size']
            }
            cinder_volume_names[key] = value
        for cinder_snapshot in cinder_snapshots:
            key = cinder_snapshot['name']
            value = {
                'id': cinder_snapshot['id'],
                'size': cinder_snapshot['volume_size'],
                'parent': cinder_snapshot['volume_name']
            }
            cinder_snapshot_names[key] = value
        payload = {
            'parent': self.san_path,
            'fields': 'name,guid,path,parent,hprService,snaplistId',
            'recursive': True
        }
        snapshots = self.nef.snapshots.list(payload)
        for snapshot in snapshots:
            safe_to_manage = True
            reason_not_safe = None
            cinder_id = None
            extra_info = None
            name = snapshot['name']
            guid = snapshot['guid']
            path = snapshot['path']
            parent = snapshot['parent']
            if parent not in cinder_volume_names:
                LOG.debug('Skip snapshot %(path)s: parent '
                          'volume %(parent)s is unmanaged',
                          {'path': path, 'parent': parent})
                continue
            for item, desc in temporary_snapshots.items():
                if utils.match_template(item, name):
                    LOG.debug('Skip %(desc)s snapshot %(path)s',
                              {'desc': desc, 'path': path})
                    continue
            for item, desc in service_snapshots.items():
                if snapshot[item]:
                    LOG.debug('Skip %(desc)s snapshot %(path)s',
                              {'desc': desc, 'path': path})
                    continue
            if name in cinder_snapshot_names:
                size = cinder_snapshot_names[name]['size']
                cinder_id = cinder_snapshot_names[name]['id']
                safe_to_manage = False
                reason_not_safe = _('Snapshot already managed')
            else:
                size = cinder_volume_names[parent]['size']
                payload = {'fields': 'clones'}
                props = self.nef.snapshots.get(path, payload)
                clones = props['clones']
                unmanaged_clones = []
                for clone in clones:
                    if clone not in cinder_volume_names:
                        unmanaged_clones.append(clone)
                if unmanaged_clones:
                    safe_to_manage = False
                    dependent_clones = ', '.join(unmanaged_clones)
                    reason_not_safe = (_('Snapshot has unmanaged '
                                         'dependent clone(s) %(clones)s')
                                       % {'clones': dependent_clones})
            reference = {
                'source-name': name,
                'source-guid': guid
            }
            source_reference = {
                'name': cinder_volume_names[parent]['name']
            }
            manageable_snapshots.append({
                'reference': reference,
                'size': size,
                'safe_to_manage': safe_to_manage,
                'reason_not_safe': reason_not_safe,
                'cinder_id': cinder_id,
                'extra_info': extra_info,
                'source_reference': source_reference
            })
        return volume_utils.paginate_entries_list(
            manageable_snapshots, marker, limit,
            offset, sort_keys, sort_dirs)

    def unmanage_snapshot(self, snapshot):
        """Removes the specified snapshot from Cinder management.

        Does not delete the underlying backend storage object.

        For most drivers, this will not need to do anything. However, some
        drivers might use this call as an opportunity to clean up any
        Cinder-specific configuration that they have associated with the
        backend storage object.

        :param snapshot: Cinder volume snapshot to unmanage
        """
        pass

    def local_path(self, volume):
        """Return local path to existing local volume."""
        raise NotImplementedError()

    def _migrate_volume(self, volume, scheme, hosts, port, path):
        """Storage assisted volume migration."""
        src_hosts = self._get_addrs()
        src_path = self._get_volume_path(volume)
        dst_path = posixpath.join(path, volume['name'])
        for dst_host in hosts:
            if dst_host in src_hosts and src_path == dst_path:
                LOG.info('Skip local migration for host %(dst_host)s: '
                         'source volume %(src_path)s and destination '
                         'volume %(dst_path)s are the same volume',
                         {'dst_host': dst_host, 'src_path': src_path,
                          'dst_path': dst_path})
                return True
        payload = {'fields': 'name'}
        try:
            self.nef.hpr.list(payload)
        except jsonrpc.NefException as error:
            LOG.error('Storage assisted volume migration '
                      'is unavailable: %(error)s',
                      {'error': error})
            return False
        service_name = '%(prefix)s-%(volume)s' % {
            'prefix': self.migration_service_prefix,
            'volume': volume['name']
        }
        service_created = False
        for dst_host in hosts:
            payload = {
                'name': service_name,
                'sourceDataset': src_path,
                'destinationDataset': dst_path,
                'type': 'scheduled'
            }
            if dst_host not in src_hosts:
                payload['isSource'] = True
                payload['remoteNode'] = {
                    'host': dst_host,
                    'port': port,
                    'proto': scheme
                }
                if self.migration_throttle:
                    payload['transportOptions'] = {
                        'throttle': self.migration_throttle * units.Mi
                    }
            try:
                self.nef.hpr.create(payload)
                service_created = True
                break
            except jsonrpc.NefException as error:
                LOG.error('Failed to create migration service '
                          'with payload %(payload)s: %(error)s',
                          {'payload': payload, 'error': error})
        service_running = False
        if service_created:
            try:
                self.nef.hpr.start(service_name)
                service_running = True
            except jsonrpc.NefException as error:
                LOG.error('Failed to start migration service '
                          '%(service_name)s: %(error)s',
                          {'service_name': service_name,
                           'error': error})
        service_success = False
        service_retries = 0
        while service_running:
            service_retries += 1
            self.nef.delay(service_retries)
            payload = {'fields': 'state,progress,runNumber,lastError'}
            try:
                service = self.nef.hpr.get(service_name, payload)
            except jsonrpc.NefException as error:
                LOG.error('Failed to stat migration service '
                          '%(service_name)s: %(error)s',
                          {'service_name': service_name,
                           'error': error})
                if service_retries > self.nef.retries:
                    break
            service_state = service['state']
            service_counter = service['runNumber']
            service_progress = service['progress']
            if service_state == 'faulted':
                service_error = service['lastError']
                LOG.error('Migration service %(service_name)s '
                          'failed with error: %(service_error)s',
                          {'service_name': service_name,
                           'service_error': service_error})
                service_running = False
            elif service_state == 'disabled' and service_counter > 0:
                LOG.info('Migration service %(service_name)s '
                         'successfully replicated %(src_path)s '
                         'to %(dst_host)s:%(dst_path)s',
                         {'service_name': service_name,
                          'src_path': src_path,
                          'dst_host': dst_host,
                          'dst_path': dst_path})
                service_running = False
                service_success = True
            else:
                LOG.info('Migration service %(service_name)s '
                         'is %(service_state)s, progress '
                         '%(service_progress)s%%',
                         {'service_name': service_name,
                          'service_state': service_state,
                          'service_progress': service_progress})
        if service_created:
            payload = {
                'destroySourceSnapshots': True,
                'destroyDestinationSnapshots': True,
                'force': True
            }
            try:
                self.nef.hpr.delete(service_name, payload)
            except jsonrpc.NefException as error:
                LOG.error('Failed to delete migration service '
                          '%(service_name)s: %(error)s',
                          {'service_name': service_name,
                           'error': error})
        if not service_success:
            return False
        try:
            self.delete_volume(volume)
        except jsonrpc.NefException as error:
            LOG.error('Failed to delete source '
                      'volume %(volume)s: %(error)s',
                      {'volume': volume['name'],
                       'error': error})
        return True

    def migrate_volume(self, ctxt, volume, host):
        """Migrate the volume to the specified host.

        Returns a boolean indicating whether the migration occurred,
        as well as model_update.

        :param ctxt: Security context
        :param volume: A dictionary describing the volume to migrate
        :param host: A dictionary describing the host to migrate to, where
                     host['host'] is its name, and host['capabilities'] is a
                     dictionary of its reported capabilities.
        """
        LOG.info('Start storage assisted volume migration '
                 'for volume %(volume)s to host %(host)s',
                 {'volume': volume['name'],
                  'host': host['host']})
        false_ret = (False, None)
        if 'capabilities' not in host:
            LOG.error('No host capabilities found for '
                      'the destination host %(host)s',
                      {'host': host['host']})
            return false_ret
        capabilities = host['capabilities']
        required_capabilities = [
            'vendor_name',
            'location_info',
            'storage_protocol',
            'free_capacity_gb'
        ]
        for capability in required_capabilities:
            if not (capability in capabilities and capabilities[capability]):
                LOG.error('Required host capability %(capability)s not '
                          'found for the destination host %(host)s',
                          {'capability': capability, 'host': host['host']})
                return false_ret
        vendor = capabilities['vendor_name']
        if vendor != self.vendor_name:
            LOG.error('Unsupported vendor %(vendor)s found '
                      'for the destination host %(host)s',
                      {'vendor': vendor, 'host': host['host']})
            return false_ret
        location = capabilities['location_info']
        try:
            san_driver, san_host, san_path = location.split(':')
        except ValueError as error:
            LOG.error('Failed to parse location info %(location)s '
                      'for the destination host %(host)s: %(error)s',
                      {'location': location, 'host': host['host'],
                       'error': error})
            return false_ret
        if not (san_driver and san_host and san_path):
            LOG.error('Incomplete location info %(location)s '
                      'found for the destination host %(host)s',
                      {'location': location, 'host': host['host']})
            return false_ret
        if san_driver != self.san_driver:
            LOG.error('Unsupported storage driver %(san_driver)s '
                      'found for the destination host %(host)s',
                      {'san_driver': san_driver,
                       'host': host['host']})
            return false_ret
        storage_protocol = capabilities['storage_protocol']
        if storage_protocol != self.storage_protocol:
            LOG.error('Unsupported storage protocol %(protocol)s '
                      'found for the destination host %(host)s',
                      {'protocol': storage_protocol,
                       'host': host['host']})
            return false_ret
        free_capacity_gb = capabilities['free_capacity_gb']
        if free_capacity_gb < volume['size']:
            LOG.error('There is not enough space available on the '
                      'destination host %(host)s to migrate volume '
                      '%(volume)s, available space: %(free)sG, '
                      'required space: %(required)sG',
                      {'host': host['host'],
                       'volume': volume['name'],
                       'free': free_capacity_gb,
                       'required': volume['size']})
            return false_ret
        nef_scheme = None
        nef_hosts = []
        nef_port = None
        if 'nef_hosts' in capabilities and capabilities['nef_hosts']:
            for nef_host in capabilities['nef_hosts'].split(','):
                nef_host = nef_host.strip()
                if nef_host:
                    nef_hosts.append(nef_host)
        elif 'nef_url' in capabilities and capabilities['nef_url']:
            url = six.moves.urllib.parse.urlparse(capabilities['nef_url'])
            if url.scheme and url.hostname and url.port:
                nef_scheme = url.scheme
                nef_hosts.append(url.hostname)
                nef_port = url.port
            else:
                for nef_host in capabilities['nef_url'].split(','):
                    nef_host = nef_host.strip()
                    if nef_host:
                        nef_hosts.append(nef_host)
        if not nef_hosts:
            LOG.error('NEF management address not found for the '
                      'destination host %(host)s: %(capabilities)s',
                      {'host': host['host'],
                       'capabilities': capabilities})
            return false_ret
        if not nef_scheme:
            if 'nef_scheme' in capabilities and capabilities['nef_scheme']:
                nef_scheme = capabilities['nef_scheme']
            else:
                nef_scheme = self.nef.scheme
        if not nef_port:
            if 'nef_port' in capabilities and capabilities['nef_port']:
                nef_port = capabilities['nef_port']
            else:
                nef_port = self.nef.port
        if self._migrate_volume(volume, nef_scheme, nef_hosts, nef_port,
                                san_path):
            return (True, None)
        return false_ret

    def update_migrated_volume(self, ctxt, volume, new_volume,
                               original_volume_status):
        """Return model update for migrated volume.

        This method should rename the back-end volume name on the
        destination host back to its original name on the source host.

        :param ctxt: The context of the caller
        :param volume: The original volume that was migrated to this backend
        :param new_volume: The migration volume object that was created on
                           this backend as part of the migration process
        :param original_volume_status: The status of the original volume
        :returns: model_update to update DB with any needed changes
        """
        try:
            self.terminate_connection(new_volume, None)
        except jsonrpc.NefException as error:
            LOG.error('Failed to terminate all connections '
                      'to migrated volume %(volume)s before '
                      'renaming: %(error)s',
                      {'volume': new_volume['name'],
                       'error': error})
            raise
        volume_renamed = False
        volume_path = self._get_volume_path(volume)
        new_volume_path = self._get_volume_path(new_volume)
        bak_volume_path = '%s-backup' % volume_path
        if volume['host'] == new_volume['host']:
            volume['_name_id'] = new_volume['id']
            payload = {'newPath': bak_volume_path}
            try:
                self.nef.volumes.rename(volume_path, payload)
            except jsonrpc.NefException as error:
                LOG.error('Failed to create backup copy of original '
                          'volume %(volume)s: %(error)s',
                          {'volume': volume['name'],
                           'error': error})
                if error.code != 'ENOENT':
                    raise error
            else:
                volume_renamed = True
        payload = {'newPath': volume_path}
        try:
            self.nef.volumes.rename(new_volume_path, payload)
        except jsonrpc.NefException as rename_error:
            LOG.error('Failed to rename temporary volume %(new_volume)s '
                      'to original %(volume)s after migration: %(error)s',
                      {'new_volume': new_volume['name'],
                       'volume': volume['name'],
                       'error': rename_error})
            if volume_renamed:
                payload = {'newPath': volume_path}
                try:
                    self.nef.volumes.rename(bak_volume_path, payload)
                except jsonrpc.NefException as restore_error:
                    LOG.error('Failed to restore backup copy of original '
                              'volume %(volume)s: %(error)s',
                              {'volume': volume['name'],
                               'error': restore_error})
            raise rename_error
        if volume_renamed:
            payload = {'newPath': new_volume_path}
            try:
                self.nef.volumes.rename(bak_volume_path, payload)
            except jsonrpc.NefException as error:
                LOG.error('Failed to rename backup copy of original '
                          'volume %(volume)s to temporary volume '
                          '%(new_volume)s: %(error)s',
                          {'volume': volume['name'],
                           'new_volume': new_volume['name'],
                           'error': error})
        return {'_name_id': None, 'provider_location': None}

    def retype(self, ctxt, volume, new_type, diff, host):
        """Retype from one volume type to another."""
        LOG.debug('Retype volume %(volume)s to host %(host)s '
                  'and volume type %(type)s with diff %(diff)s',
                  {'volume': volume['name'], 'host': host,
                   'type': new_type['name'], 'diff': diff})
        self._update_volume_props(volume, new_type)
        return True, None

    def _init_vendor_properties(self):
        """Create a dictionary of vendor unique properties.

        This method creates a dictionary of vendor unique properties
        and returns both created dictionary and vendor name.
        Returned vendor name is used to check for name of vendor
        unique properties.

        - Vendor name shouldn't include colon(:) because of the separator
          and it is automatically replaced by underscore(_).
          ex. abc:d -> abc_d
        - Vendor prefix is equal to vendor name.
          ex. abcd
        - Vendor unique properties must start with vendor prefix + ':'.
          ex. abcd:maxIOPS

        Each backend driver needs to override this method to expose
        its own properties using _set_property() like this:

        self._set_property(
            properties,
            "vendorPrefix:specific_property",
            "Title of property",
            _("Description of property"),
            "type")

        : return dictionary of vendor unique properties
        : return vendor name
        """
        vendor_properties = {}
        namespace = self.nef.volumes.namespace
        items = self.nef.volumes.properties + self.nef.logicalunits.properties
        keys = ['enum', 'default', 'minimum', 'maximum']
        for item in items:
            spec = {}
            for key in keys:
                if key in item:
                    spec[key] = item[key]
            if 'cfg' in item:
                key = item['cfg']
                value = self.configuration.safe_get(key)
                if value not in [None, '']:
                    spec['default'] = value
            elif 'api' in item:
                api = item['api']
                if api in self.san_stat:
                    value = self.san_stat[api]
                    spec['default'] = value
            LOG.debug('Initialize vendor capabilities for '
                      '%(product)s %(protocol)s backend: '
                      '%(type)s %(name)s property %(spec)s',
                      {'product': self.product_name,
                       'protocol': self.storage_protocol,
                       'type': item['type'],
                       'name': item['name'],
                       'spec': spec})
            self._set_property(
                vendor_properties,
                item['name'],
                item['title'],
                item['description'],
                item['type'],
                **spec
            )
        return vendor_properties, namespace

    def _get_volume_type_specs(self, volume, volume_type=None):
        if volume_type and 'id' in volume_type:
            type_id = volume_type['id']
        elif 'volume_type_id' in volume:
            type_id = volume['volume_type_id']
        else:
            type_id = None
        if type_id:
            return volume_types.get_volume_type_extra_specs(type_id)
        return {}

    def _get_lu_specs(self, volume, volume_type=None):
        payload = {}
        items = self.nef.logicalunits.properties
        specs = self._get_volume_type_specs(volume, volume_type)
        for item in items:
            if 'api' not in item:
                continue
            api = item['api']
            name = item['name']
            if name in specs:
                spec = specs[name]
                value = self._check_volume_spec(spec, item)
            elif 'cfg' in item:
                key = item['cfg']
                value = self.configuration.safe_get(key)
                if value in [None, '']:
                    continue
            else:
                continue
            payload[api] = value
        LOG.debug('LU properties for %(volume)s: %(payload)s',
                  {'volume': volume['name'], 'payload': payload})
        return payload

    def _get_volume_specs(self, volume, volume_type=None):
        payload = {}
        items = self.nef.volumes.properties
        specs = self._get_volume_type_specs(volume, volume_type)
        for item in items:
            if 'api' not in item:
                continue
            api = item['api']
            name = item['name']
            if name in specs:
                spec = specs[name]
                value = self._check_volume_spec(spec, item)
            elif 'cfg' in item:
                key = item['cfg']
                value = self.configuration.safe_get(key)
                if value in [None, '']:
                    continue
            elif volume_type and api in self.san_stat:
                value = self.san_stat[api]
            else:
                continue
            payload[api] = value
        LOG.debug('Volume properties for %(volume)s: %(payload)s',
                  {'volume': volume['name'], 'payload': payload})
        return payload

    def _check_volume_spec(self, value, prop):
        name = prop['name']
        code = 'EINVAL'
        if prop['type'] == 'integer':
            try:
                value = int(value)
            except (TypeError, ValueError):
                message = (_('Invalid non-integer value %(value)s for '
                             'vendor property name %(name)s')
                           % {'value': value, 'name': name})
                raise jsonrpc.NefException(code=code, message=message)
            if 'minimum' in prop:
                minimum = prop['minimum']
                if value < minimum:
                    message = (_('Integer value %(value)s is less than '
                                 'allowed minimum %(minimum)s for vendor '
                                 'property name %(name)s')
                               % {'value': value, 'minimum': minimum,
                                  'name': name})
                    raise jsonrpc.NefException(code=code, message=message)
            if 'maximum' in prop:
                maximum = prop['maximum']
                if value > maximum:
                    message = (_('Integer value %(value)s is greater than '
                                 'allowed maximum %(maximum)s for vendor '
                                 'property name %(name)s')
                               % {'value': value, 'maximum': maximum,
                                  'name': name})
                    raise jsonrpc.NefException(code=code, message=message)
        elif prop['type'] == 'string':
            try:
                value = str(value)
            except UnicodeEncodeError:
                message = (_('Invalid non-ASCII value %(value)s for vendor '
                             'property name %(name)s')
                           % {'value': value, 'name': name})
                raise jsonrpc.NefException(code=code, message=message)
        elif prop['type'] == 'boolean':
            words = value.split()
            if len(words) == 2 and words[0] == '<is>':
                value = words[1]
            try:
                value = strutils.bool_from_string(value, strict=True)
            except ValueError:
                message = (_('Invalid non-boolean value %(value)s for vendor '
                             'property name %(name)s')
                           % {'value': value, 'name': name})
                raise jsonrpc.NefException(code=code, message=message)
        if 'enum' in prop:
            enum = prop['enum']
            if value not in enum:
                message = (_('Value %(value)s is out of allowed enumeration '
                             '%(enum)s for vendor property name %(name)s')
                           % {'value': value, 'enum': enum, 'name': name})
                raise jsonrpc.NefException(code=code, message=message)
        return value

    def _get_backend_name(self):
        backend_name = self.configuration.safe_get('volume_backend_name')
        if not backend_name:
            LOG.error('Failed to get configured volume backend name')
            backend_name = '%(product)s_%(protocol)s' % {
                'product': self.product_name,
                'protocol': self.storage_protocol
            }
        return backend_name
