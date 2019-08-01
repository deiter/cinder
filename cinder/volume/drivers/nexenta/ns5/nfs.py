# Copyright 2019 Nexenta Systems, Inc.
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

import errno
import ipaddress
import os
import posixpath
import sys
import uuid

from oslo_log import log as logging
from oslo_utils import strutils
from oslo_utils import units
import six

from cinder import context
from cinder import coordination
from cinder.i18n import _
from cinder.image import image_utils
from cinder import interface
from cinder import objects
from cinder.privsep import fs
from cinder.volume.drivers.nexenta.ns5 import jsonrpc
from cinder.volume.drivers.nexenta import options
from cinder.volume.drivers import nfs
from cinder.volume import utils
from cinder.volume import volume_types

LOG = logging.getLogger(__name__)

VOLUME_FILE_NAME = 'volume'
VOLUME_FORMAT_RAW = 'raw'
VOLUME_FORMAT_QCOW = 'qcow'
VOLUME_FORMAT_QCOW2 = 'qcow2'
VOLUME_FORMAT_PARALLELS = 'parallels'
VOLUME_FORMAT_VDI = 'vdi'
VOLUME_FORMAT_VHDX = 'vhdx'
VOLUME_FORMAT_VMDK = 'vmdk'
VOLUME_FORMAT_VPC = 'vpc'
VOLUME_FORMAT_QED = 'qed'

@interface.volumedriver
class NexentaNfsDriver(nfs.NfsDriver):
    """Executes volume driver commands on Nexenta Appliance.

    Version history:

    .. code-block:: none

        1.0.0 - Initial driver version.
        1.1.0 - Support for extend volume.
        1.2.0 - Added HTTPS support.
              - Added use of sessions for REST calls.
              - Added abandoned volumes and snapshots cleanup.
        1.3.0 - Failover support.
        1.4.0 - Migrate volume support and new NEF API calls.
        1.5.0 - Revert to snapshot support.
        1.6.0 - Get mountPoint from API to support old style mount points.
              - Mount and umount shares on each operation to avoid mass
                mounts on controller. Clean up mount folders on delete.
        1.6.1 - Fixed volume from image creation.
        1.6.2 - Removed redundant share mount from initialize_connection.
        1.6.3 - Adapted NexentaException for the latest Cinder.
        1.6.4 - Fixed volume mount/unmount.
        1.6.5 - Added driver_ssl_cert_verify for HA failover.
        1.6.6 - Destroy unused snapshots after deletion of it's last clone.
        1.6.7 - Fixed volume migration for HA environment.
        1.6.8 - Added deferred deletion for snapshots.
        1.6.9 - Fixed race between volume/clone deletion.
        1.7.0 - Added consistency group support.
        1.7.1 - Removed redundant hpr/activate call from initialize_connection.
        1.7.2 - Merged upstream changes for umount.
        1.8.0 - Refactored NFS driver.
              - Added pagination support.
              - Added configuration parameters for REST API connect/read
                timeouts, connection retries and backoff factor.
              - Fixed HA failover.
              - Added retries on EBUSY errors.
              - Fixed HTTP authentication.
              - Disabled non-blocking mandatory locks.
              - Added coordination for dataset operations.
        1.8.1 - Support for NexentaStor tenants.
        1.8.2 - Added manage/unmanage/manageable-list volume/snapshot support.
        1.8.3 - Added consistency group capability to generic volume group.
        1.8.4 - Refactored storage assisted volume migration.
              - Added support for volume retype.
              - Added support for volume type extra specs.
              - Added vendor capabilities support.
        1.8.5 - Fixed NFS protocol version for generic volume migration.
        1.8.6 - Fixed post-migration volume mount.
        1.8.7 - Added workaround for pagination.
        1.8.8 - Improved error messages.
              - Improved compatibility with initial driver versions.
              - Added throttle for storage assisted volume migration.
        1.8.9 - Added qcow2 format support.
              - Fixed space reservation calculation.
    """

    VERSION = '1.8.9'
    CI_WIKI_NAME = "Nexenta_CI"

    vendor_name = 'Nexenta'
    product_name = 'NexentaStor5'
    storage_protocol = 'NFS'
    driver_volume_type = 'nfs'

    def __init__(self, *args, **kwargs):
        super(NexentaNfsDriver, self).__init__(*args, **kwargs)
        if not self.configuration:
            message = (_('%(product_name)s %(storage_protocol)s '
                         'backend configuration not found')
                       % {'product_name': self.product_name,
                          'storage_protocol': self.storage_protocol})
            raise jsonrpc.NefException(code='ENODATA', message=message)
        self.configuration.append_config_values(
            options.NEXENTA_CONNECTION_OPTS)
        self.configuration.append_config_values(
            options.NEXENTA_NFS_OPTS)
        self.configuration.append_config_values(
            options.NEXENTA_DATASET_OPTS)
        self.nef = None
        self.root = None
        self.driver_name = self.__class__.__name__
        self.nas_host = self.configuration.nas_host
        self.nas_path = self.configuration.nas_share_path
        self.mount_point_base = self.configuration.nexenta_mount_point_base
        self.group_snapshot_template = (
            self.configuration.nexenta_group_snapshot_template)
        self.origin_snapshot_template = (
            self.configuration.nexenta_origin_snapshot_template)
        self.migration_service_prefix = (
            self.configuration.nexenta_migration_service_prefix)
        self.migration_throttle = (
            self.configuration.nexenta_migration_throttle)

    @staticmethod
    def get_driver_options():
        return (
            options.NEXENTA_CONNECTION_OPTS +
            options.NEXENTA_NFS_OPTS +
            options.NEXENTA_DATASET_OPTS
        )

    def do_setup(self, context):
        self.nef = jsonrpc.NefProxy(self.driver_volume_type,
                                    self.nas_path,
                                    self.configuration)

    def check_for_setup_error(self):
        """Check root filesystem, NFS service and NFS share."""
        self.root = self.nef.filesystems.get(self.nas_path)
        if self.root['mountPoint'] == 'none':
            message = (_('NFS root filesystem %(path)s is not writable')
                       % {'path': self.root['mountPoint']})
            raise jsonrpc.NefException(code='ENOENT', message=message)
        if not self.root['isMounted']:
            message = (_('NFS root filesystem %(path)s is not mounted')
                       % {'path': self.root['mountPoint']})
            raise jsonrpc.NefException(code='ENOTDIR', message=message)
        payload = {}
        if self.root['nonBlockingMandatoryMode']:
            payload['nonBlockingMandatoryMode'] = False
        if self.root['smartCompression']:
            payload['smartCompression'] = False
        if payload:
            self.nef.filesystems.set(self.nas_path, payload)
        service = self.nef.services.get('nfs')
        if service['state'] != 'online':
            message = (_('NFS server service is not online: %(state)s')
                       % {'state': service['state']})
            raise jsonrpc.NefException(code='ESRCH', message=message)
        share = self.nef.nfs.get(self.nas_path)
        if share['shareState'] != 'online':
            message = (_('NFS share %(share)s is not online: %(state)s')
                       % {'share': self.nas_path,
                          'state': share['shareState']})
            raise jsonrpc.NefException(code='ESRCH', message=message)

    def _get_volume_reservation(self, volume):
        """Calculates the correct reservation size for given volume size.

        Its purpose is to reserve additional space for volume metadata
        so volume don't unexpectedly run out of room. This function is
        a copy of the volsize_to_reservation function in libzfs_dataset.c

        :param volume: volume reference
        :returns: reservation size
        """
        volume_path = self._get_volume_path(volume)
        filesystem = self.nef.filesystems.get(volume_path)
        block_size = filesystem['recordSize']
        data_copies = filesystem['dataCopies']
        reservation = volume['size'] * units.Gi
        numdb = 7
        dn_max_indblkshift = 17
        spa_blkptrshift = 7
        spa_dvas_per_bp = 3
        dnodes_per_level_shift = dn_max_indblkshift - spa_blkptrshift
        dnodes_per_level = 1 << dnodes_per_level_shift
        nblocks = reservation // block_size
        while nblocks > 1:
            nblocks += dnodes_per_level - 1
            nblocks //= dnodes_per_level
            numdb += nblocks
        numdb *= min(spa_dvas_per_bp, data_copies + 1)
        reservation *= data_copies
        numdb *= 1 << dn_max_indblkshift
        reservation += numdb
        return reservation

    def _get_meta_size(self, volume, volume_format):
        """Calculates the metadata size for given volume format.

        Its purpose is to reserve additional space for volume metadata
        so volume don't unexpectedly run out of room. This function is
        a copy of the qcow2_calc_prealloc_size function in qcow2.c

        :param volume: volume reference
        :volume_format: volume format
        :returns: metadata size
        """
        def div_roundup(numerator, denominator):
            return (numerator + denominator - 1) // denominator

        def roundup(numerator, denominator):
            return div_roundup(numerator, denominator) * denominator

        volume_size = volume['size'] * units.Gi
        if volume_format == VOLUME_FORMAT_RAW:
            meta_size = 0
        elif volume_format == VOLUME_FORMAT_QCOW:
            meta_size = 48 + 4 * volume_size // units.Mi
        elif volume_format == VOLUME_FORMAT_QCOW2:
            cluster_size = 64 * units.Ki
            refcount_size = 4
            int_size = (sys.maxsize.bit_length() + 1) // 8
            meta_size = 0
            aligned_volume_size = roundup(volume_size, cluster_size)
            meta_size += cluster_size
            blocks_per_table = cluster_size // int_size
            clusters = aligned_volume_size // cluster_size
            nl2e = roundup(clusters, blocks_per_table)
            meta_size += nl2e * int_size
            clusters = nl2e * int_size // cluster_size
            nl1e = roundup(clusters, blocks_per_table)
            meta_size += nl1e * int_size
            clusters = (aligned_volume_size + meta_size) // cluster_size
            refcounts_per_block = 8 * cluster_size // (1 << refcount_size)
            table = blocks = first = 0
            last = 1
            while first != last:
                last = first
                first = clusters + blocks + table
                blocks = div_roundup(first, refcounts_per_block)
                table = div_roundup(blocks, blocks_per_table)
                first = clusters + blocks + table
            meta_size += (blocks + table) * cluster_size
        elif volume_format == VOLUME_FORMAT_PARALLELS:
            meta_size = (1 + volume_size // units.Gi // 256) * units.Mi
        elif volume_format == VOLUME_FORMAT_VDI:
            meta_size = 512 + 4 * volume_size // units.Mi
        elif volume_format == VOLUME_FORMAT_VHDX:
            meta_size = 8 * units.Mi
        elif volume_format == VOLUME_FORMAT_VMDK:
            meta_size = 192 * (units.Ki + volume_size // units.Mi)
        elif volume_format == VOLUME_FORMAT_VPC:
            meta_size = 512 + 2 * (units.Ki + volume_size // units.Mi)
        elif volume_format == VOLUME_FORMAT_QED:
            meta_size = 320 * units.Ki
        else:
            message = (_('Volume format %(volume_format)s is not supported')
                       % {'volume_format': volume_format})
            raise jsonrpc.NefException(code='EINVAL', message=message)
        return meta_size

    @coordination.synchronized('{self.nef.lock}')
    def create_volume(self, volume):
        """Creates a volume.

        :param volume: volume reference
        """
        volume_path = self._get_volume_path(volume)
        properties = self.nef.filesystems.properties
        payload = self._get_vendor_properties(volume, properties)
        sparsed_volume = payload.pop('sparseVolume')
        volume_format = payload.pop('volumeFormat')
        specs = {'size': '%sG' % volume['size']}
        if volume_format == VOLUME_FORMAT_QCOW2:
            specs['preallocation'] = 'metadata'
        volume_options = ','.join(['%s=%s' % _ for _ in specs.items()])
        payload['path'] = volume_path
        self.nef.filesystems.create(payload)
        error_code = error_message = None
        try:
            self._set_volume_acl(volume)
            nfs_share, mount_point, volume_file = self._mount_volume(volume)
            self._execute('qemu-img', 'create', '-f', volume_format, '-o',
                          volume_options, volume_file, run_as_root=True)
            if sparsed_volume:
                return
            reservation = self._get_volume_reservation(volume)
            reservation += self._get_meta_size(volume, volume_format)
            payload = {'referencedReservationSize': reservation}
            self.nef.filesystems.set(volume_path, payload)
        except jsonrpc.NefException as error:
            error_code = error.code
            error_message = error.message
        except OSError as error:
            error_code = errno.errorcode[error.errno]
            error_message = error.strerror
        finally:
            self._unmount_volume(volume, nfs_share, mount_point)
        if not error_code:
            return
        payload = {'force': True}
        try:
            self.nef.filesystems.delete(volume_path, payload)
        except jsonrpc.NefException as error:
            LOG.error('Failed to delete volume %(volume)s: %(error)s',
                      {'volume': volume['name'], 'error': error})
        message = (_('Failed to create volume %(volume)s: %(error)s')
                   % {'volume': volume['name'], 'error': error_message})
        raise jsonrpc.NefException(code=error_code, message=message)

    def copy_image_to_volume(self, context, volume, image_service, image_id):
        LOG.debug('Copy image %(image)s to volume %(volume)s',
                  {'image': image_id, 'volume': volume['name']})
        nfs_share, mount_point, volume_file = self._mount_volume(volume)
        super(NexentaNfsDriver, self).copy_image_to_volume(
            context, volume, image_service, image_id)
        self._unmount_volume(volume, nfs_share, mount_point)

    def copy_volume_to_image(self, context, volume, image_service, image_meta):
        LOG.debug('Copy volume %(volume)s to image %(image)s',
                  {'volume': volume['name'], 'image': image_meta['id']})
        nfs_share, mount_point, volume_file = self._mount_volume(volume)
        super(NexentaNfsDriver, self).copy_volume_to_image(
            context, volume, image_service, image_meta)
        self._unmount_volume(volume, nfs_share, mount_point)

    def _ensure_share_unmounted(self, nfs_share, mount_point=None):
        """Ensure that NFS share is unmounted on the host.

        :param nfs_share: NFS share
        :param mount_point: mount point
        """
        if mount_point is None:
            mount_point = self._get_mount_point_for_share(nfs_share)
        if mount_point not in self._remotefsclient._read_mounts():
            LOG.debug('NFS share %(nfs_share)s is not mounted '
                      'on mount point %(mount_point)s',
                      {'nfs_share': nfs_share,
                       'mount_point': mount_point})
            return
        attempts = max(1, self.configuration.nfs_mount_attempts)
        for attempt in range(attempts):
            try:
                fs.umount(mount_point)
                LOG.debug('NFS share %(nfs_share)s has been unmounted '
                          'from mount point %(mount_point)s',
                          {'nfs_share': nfs_share,
                           'mount_point': mount_point})
                break
            except Exception as error:
                if attempt == attempts - 1:
                    LOG.error('Failed to unmount NFS share %(nfs_share)s '
                              'from mount point %(mount_point)s after '
                              '%(attempts)s attempts: %(error)s',
                              {'nfs_share': nfs_share,
                               'mount_point': mount_point,
                               'attempts': attempts,
                               'error': error})
                    raise
                LOG.error('Unmount attempt %(attempt)s failed: %(error)s, '
                          'retrying unmount NFS share %(nfs_share)s from '
                          'mount point %(mount_point)s',
                          {'attempt': attempt,
                           'error': error,
                           'nfs_share': nfs_share,
                           'mount_point': mount_point})
                self.nef.delay(attempt)
        self._delete(mount_point)

    def _mount_volume(self, volume):
        """Ensure that volume is activated and mounted on the host."""
        nfs_share = self._get_volume_share(volume)
        self._ensure_share_mounted(nfs_share)
        mount_point = self._get_mount_point_for_share(nfs_share)
        volume_file = os.path.join(mount_point, VOLUME_FILE_NAME)
        return nfs_share, mount_point, volume_file

    def _remount_volume(self, volume):
        """Workaround for NEX-16457."""
        volume_path = self._get_volume_path(volume)
        self.nef.filesystems.unmount(volume_path)
        self.nef.filesystems.mount(volume_path)

    def _unmount_volume(self, volume, nfs_share=None, mount_point=None):
        """Ensure that volume is unmounted on the host."""
        if nfs_share is None and mount_point is None:
            try:
                nfs_share = self._get_volume_share(volume)
            except jsonrpc.NefException:
                nfs_share = '%(host)s:%(path)s' % {
                    'host': self.nas_host,
                    'path': posixpath.join(
                        self.root['mountPoint'],
                        volume['name']
                    )
                }
        self._ensure_share_unmounted(nfs_share, mount_point)

    def _migrate_volume(self, volume, scheme, hosts, port, path):
        """Storage assisted volume migration."""
        src_hosts = self._get_host_addresses()
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
            self.nef.delay(service_retries)
            service_retries += 1
            payload = {'fields': 'state,progress,runNumber'}
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

    def migrate_volume(self, context, volume, host):
        """Migrate the volume to the specified host.

        Returns a boolean indicating whether the migration occurred,
        as well as model_update.

        :param context: Security context
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
            driver, nas_host, nas_path = location.split(':')
        except ValueError as error:
            LOG.error('Failed to parse location info %(location)s '
                      'for the destination host %(host)s: %(error)s',
                      {'location': location, 'host': host['host'],
                       'error': error})
            return false_ret
        if not (driver and nas_host and nas_path):
            LOG.error('Incomplete location info %(location)s '
                      'found for the destination host %(host)s',
                      {'location': location, 'host': host['host']})
            return false_ret
        if driver != self.driver_name:
            LOG.error('Unsupported storage driver %(driver)s '
                      'found for the destination host %(host)s',
                      {'driver': driver, 'host': host['host']})
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
                                nas_path):
            return (True, None)
        return false_ret

    def create_export(self, context, volume, connector):
        """Driver entry point to get the export info for a new volume."""
        pass

    def ensure_export(self, context, volume):
        """Driver entry point to get the export info for an existing volume."""
        pass

    def remove_export(self, context, volume):
        """Driver entry point to remove an export for a volume."""
        pass

    def terminate_connection(self, volume, connector, **kwargs):
        """Terminate a connection to a volume.

        :param volume: a volume object
        :param connector: a connector object
        :returns: dictionary of connection information
        """
        LOG.debug('Terminate volume connection for %(volume)s',
                  {'volume': volume['name']})
        self._unmount_volume(volume)

    def initialize_connection(self, volume, connector):
        """Terminate a connection to a volume.

        :param volume: a volume object
        :param connector: a connector object
        :returns: dictionary of connection information
        """
        # TODO
        LOG.debug('Initialize volume connection for %(volume)s '
                  'and connector %(connector)s',
                  {'volume': volume['name'], 'connector': connector})
        nfs_share, mount_point, volume_file = self._mount_volume(volume)
        volume_info = image_utils.qemu_img_info(volume_file,
                                                run_as_root=True,
                                                force_share=True)
        self._unmount_volume(volume, nfs_share, mount_point)
        data = {
            'export': nfs_share,
            'format': volume_info.file_format,
            'name': VOLUME_FILE_NAME
        }
        nfs_options = self.configuration.safe_get('nfs_mount_options')
        nas_options = self.configuration.safe_get('nas_mount_options')
        if nfs_options and nas_options:
            LOG.debug('Overriding NFS mount options for volume %(volume)s: '
                      'nfs_mount_options = "%(nfs_options)s" with '
                      'nas_mount_options = "%(nas_options)s"',
                      {'volume': volume['name'],
                       'nfs_options': nfs_options,
                       'nas_options': nas_options})
        if nas_options:
            data['options'] = '-o %s' % nas_options
        elif nfs_options:
            data['options'] = '-o %s' % nfs_options
        connection_info = {
            'driver_volume_type': self.driver_volume_type,
            'mount_point_base': self.mount_point_base,
            'data': data
        }
        return connection_info

    @coordination.synchronized('{self.nef.lock}')
    def delete_volume(self, volume):
        """Deletes a volume.

        :param volume: volume reference
        """
        volume_path = self._get_volume_path(volume)
        self._unmount_volume(volume)
        delete_payload = {'force': True, 'snapshots': True}
        try:
            self.nef.filesystems.delete(volume_path, delete_payload)
        except jsonrpc.NefException as error:
            if error.code != 'EEXIST':
                raise
            snapshots_tree = {}
            snapshots_payload = {'parent': volume_path, 'fields': 'path'}
            snapshots = self.nef.snapshots.list(snapshots_payload)
            for snapshot in snapshots:
                clones_payload = {'fields': 'clones,creationTxg'}
                data = self.nef.snapshots.get(snapshot['path'], clones_payload)
                if data['clones']:
                    snapshots_tree[data['creationTxg']] = data['clones'][0]
            if snapshots_tree:
                clone_path = snapshots_tree[max(snapshots_tree)]
                self.nef.filesystems.promote(clone_path)
            self.nef.filesystems.delete(volume_path, delete_payload)

    def _delete(self, path):
        """Override parent method for safe remove mountpoint."""
        try:
            os.rmdir(path)
            LOG.debug('The mountpoint %(path)s has been successfully removed',
                      {'path': path})
        except OSError as error:
            LOG.error('Failed to remove mountpoint %(path)s: %(error)s',
                      {'path': path, 'error': error.strerror})

    def extend_volume(self, volume, new_size):
        """Extend an existing volume.

        :param volume: volume reference
        :param new_size: volume new size in GB
        """
        LOG.info('Extend volume %(volume)s, new size: %(size)sGB',
                 {'volume': volume['name'], 'size': new_size})
        nfs_share, mount_point, volume_file = self._mount_volume(volume)
        try:
            image_utils.resize_image(volume_file, new_size, run_as_root=True)
        except OSError as error:
            LOG.error('Failed to extend backend file %(volume_file)s '
                      'for volume %(volume)s: %(error)s',
                      {'volume_file': volume_file,
                       'volume': volume['name'],
                       'error': error.strerror})
            raise
        finally:
            self._unmount_volume(volume, nfs_share, mount_point)

    @coordination.synchronized('{self.nef.lock}')
    def create_snapshot(self, snapshot):
        """Creates a snapshot.

        :param snapshot: snapshot reference
        """
        snapshot_path = self._get_snapshot_path(snapshot)
        payload = {'path': snapshot_path}
        self.nef.snapshots.create(payload)

    @coordination.synchronized('{self.nef.lock}')
    def delete_snapshot(self, snapshot):
        """Deletes a snapshot.

        :param snapshot: snapshot reference
        """
        snapshot_path = self._get_snapshot_path(snapshot)
        payload = {'defer': True}
        self.nef.snapshots.delete(snapshot_path, payload)

    def snapshot_revert_use_temp_snapshot(self):
        # Considering that NexentaStor based drivers use COW images
        # for storing snapshots, having chains of such images,
        # creating a backup snapshot when reverting one is not
        # actually helpful.
        return False

    def revert_to_snapshot(self, context, volume, snapshot):
        """Revert volume to snapshot."""
        volume_path = self._get_volume_path(volume)
        payload = {'snapshot': snapshot['name']}
        self.nef.filesystems.rollback(volume_path, payload)

    @coordination.synchronized('{self.nef.lock}')
    def create_volume_from_snapshot(self, volume, snapshot):
        """Create new volume from other's snapshot on appliance.

        :param volume: reference of volume to be created
        :param snapshot: reference of source snapshot
        """
        LOG.debug('Create volume %(volume)s from snapshot %(snapshot)s',
                  {'volume': volume['name'], 'snapshot': snapshot['name']})
        snapshot_path = self._get_snapshot_path(snapshot)
        clone_path = self._get_volume_path(volume)
        payload = {'targetPath': clone_path}
        self.nef.snapshots.clone(snapshot_path, payload)
        self._remount_volume(volume)
        self._set_volume_acl(volume)
        if volume['size'] > snapshot['volume_size']:
            new_size = volume['size']
            volume['size'] = snapshot['volume_size']
            self.extend_volume(volume, new_size)
            volume['size'] = new_size

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
        except jsonrpc.NefException as error:
            LOG.error('Failed to create clone %(clone)s '
                      'from volume %(volume)s: %(error)s',
                      {'clone': volume['name'],
                       'volume': src_vref['name'],
                       'error': error})
            raise
        finally:
            try:
                self.delete_snapshot(snapshot)
            except jsonrpc.NefException as error:
                LOG.error('Failed to delete temporary snapshot '
                          '%(volume)s@%(snapshot)s: %(error)s',
                          {'volume': src_vref['name'],
                           'snapshot': snapshot['name'],
                           'error': error})

    def create_consistencygroup(self, context, group):
        """Creates a consistency group.

        :param context: the context of the caller.
        :param group: the dictionary of the consistency group to be created.
        :returns: group_model_update
        """
        group_model_update = {}
        return group_model_update

    def create_group(self, context, group):
        """Creates a group.

        :param context: the context of the caller.
        :param group: the group object.
        :returns: model_update
        """
        return self.create_consistencygroup(context, group)

    def delete_consistencygroup(self, context, group, volumes):
        """Deletes a consistency group.

        :param context: the context of the caller.
        :param group: the dictionary of the consistency group to be deleted.
        :param volumes: a list of volume dictionaries in the group.
        :returns: group_model_update, volumes_model_update
        """
        group_model_update = {}
        volumes_model_update = []
        for volume in volumes:
            self.delete_volume(volume)
        return group_model_update, volumes_model_update

    def delete_group(self, context, group, volumes):
        """Deletes a group.

        :param context: the context of the caller.
        :param group: the group object.
        :param volumes: a list of volume objects in the group.
        :returns: model_update, volumes_model_update
        """
        return self.delete_consistencygroup(context, group, volumes)

    def update_consistencygroup(self, context, group, add_volumes=None,
                                remove_volumes=None):
        """Updates a consistency group.

        :param context: the context of the caller.
        :param group: the dictionary of the consistency group to be updated.
        :param add_volumes: a list of volume dictionaries to be added.
        :param remove_volumes: a list of volume dictionaries to be removed.
        :returns: group_model_update, add_volumes_update, remove_volumes_update
        """
        group_model_update = {}
        add_volumes_update = []
        remove_volumes_update = []
        return group_model_update, add_volumes_update, remove_volumes_update

    def update_group(self, context, group, add_volumes=None,
                     remove_volumes=None):
        """Updates a group.

        :param context: the context of the caller.
        :param group: the group object.
        :param add_volumes: a list of volume objects to be added.
        :param remove_volumes: a list of volume objects to be removed.
        :returns: model_update, add_volumes_update, remove_volumes_update
        """
        return self.update_consistencygroup(context, group, add_volumes,
                                            remove_volumes)

    def create_cgsnapshot(self, context, cgsnapshot, snapshots):
        """Creates a consistency group snapshot.

        :param context: the context of the caller.
        :param cgsnapshot: the dictionary of the cgsnapshot to be created.
        :param snapshots: a list of snapshot dictionaries in the cgsnapshot.
        :returns: group_model_update, snapshots_model_update
        """
        group_model_update = {}
        snapshots_model_update = []
        cgsnapshot_name = self.group_snapshot_template % cgsnapshot['id']
        cgsnapshot_path = '%s@%s' % (self.nas_path, cgsnapshot_name)
        create_payload = {'path': cgsnapshot_path, 'recursive': True}
        self.nef.snapshots.create(create_payload)
        for snapshot in snapshots:
            volume_name = snapshot['volume_name']
            volume_path = posixpath.join(self.nas_path, volume_name)
            snapshot_name = snapshot['name']
            snapshot_path = '%s@%s' % (volume_path, cgsnapshot_name)
            rename_payload = {'newName': snapshot_name}
            self.nef.snapshots.rename(snapshot_path, rename_payload)
        delete_payload = {'defer': True, 'recursive': True}
        self.nef.snapshots.delete(cgsnapshot_path, delete_payload)
        return group_model_update, snapshots_model_update

    def create_group_snapshot(self, context, group_snapshot, snapshots):
        """Creates a group_snapshot.

        :param context: the context of the caller.
        :param group_snapshot: the GroupSnapshot object to be created.
        :param snapshots: a list of Snapshot objects in the group_snapshot.
        :returns: model_update, snapshots_model_update
        """
        return self.create_cgsnapshot(context, group_snapshot, snapshots)

    def delete_cgsnapshot(self, context, cgsnapshot, snapshots):
        """Deletes a consistency group snapshot.

        :param context: the context of the caller.
        :param cgsnapshot: the dictionary of the cgsnapshot to be created.
        :param snapshots: a list of snapshot dictionaries in the cgsnapshot.
        :returns: group_model_update, snapshots_model_update
        """
        group_model_update = {}
        snapshots_model_update = []
        for snapshot in snapshots:
            self.delete_snapshot(snapshot)
        return group_model_update, snapshots_model_update

    def delete_group_snapshot(self, context, group_snapshot, snapshots):
        """Deletes a group_snapshot.

        :param context: the context of the caller.
        :param group_snapshot: the GroupSnapshot object to be deleted.
        :param snapshots: a list of snapshot objects in the group_snapshot.
        :returns: model_update, snapshots_model_update
        """
        return self.delete_cgsnapshot(context, group_snapshot, snapshots)

    def create_consistencygroup_from_src(self, context, group, volumes,
                                         cgsnapshot=None, snapshots=None,
                                         source_cg=None, source_vols=None):
        """Creates a consistency group from source.

        :param context: the context of the caller.
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
            snapshot_path = '%s@%s' % (self.nas_path, snapshot_name)
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

    def create_group_from_src(self, context, group, volumes,
                              group_snapshot=None, snapshots=None,
                              source_group=None, source_vols=None):
        """Creates a group from source.

        :param context: the context of the caller.
        :param group: the Group object to be created.
        :param volumes: a list of Volume objects in the group.
        :param group_snapshot: the GroupSnapshot object as source.
        :param snapshots: a list of snapshot objects in group_snapshot.
        :param source_group: the Group object as source.
        :param source_vols: a list of volume objects in the source_group.
        :returns: model_update, volumes_model_update
        """
        return self.create_consistencygroup_from_src(context, group, volumes,
                                                     group_snapshot, snapshots,
                                                     source_group, source_vols)

    def local_path(self, volume):
        """Get volume path (mounted locally fs path) for given volume.

        :param volume: volume reference
        """
        share = self._get_volume_share(volume)
        mount_point = self._get_mount_point_for_share(share)
        volume_file = os.path.join(mount_point, VOLUME_FILE_NAME)
        return volume_file

    def _set_volume_acl(self, volume):
        """Sets access permissions for given volume.

        :param volume: volume reference
        """
        volume_path = self._get_volume_path(volume)
        payload = {
            'type': 'allow',
            'principal': 'everyone@',
            'permissions': [
                'full_set'
            ],
            'flags': [
                'file_inherit',
                'dir_inherit'
            ]
        }
        self.nef.filesystems.acl(volume_path, payload)

    def _get_volume_share(self, volume):
        """Return NFS share path for the volume."""
        volume_path = self._get_volume_path(volume)
        get_payload = {'fields': 'mountPoint,isMounted'}
        filesystem = self.nef.filesystems.get(volume_path, get_payload)
        if filesystem['mountPoint'] == 'none':
            activate_payload = {'datasetName': volume_path}
            self.nef.hpr.activate(activate_payload)
            filesystem = self.nef.filesystems.get(volume_path, get_payload)
        if not filesystem['isMounted']:
            self.nef.filesystems.mount(volume_path)
        share = '%s:%s' % (self.nas_host, filesystem['mountPoint'])
        return share

    def _get_volume_path(self, volume):
        """Return ZFS dataset path for the volume."""
        return posixpath.join(self.nas_path, volume['name'])

    def _get_snapshot_path(self, snapshot):
        """Return ZFS snapshot path for the snapshot."""
        volume_name = snapshot['volume_name']
        snapshot_name = snapshot['name']
        volume_path = posixpath.join(self.nas_path, volume_name)
        return '%s@%s' % (volume_path, snapshot_name)

    def get_volume_stats(self, refresh=False):
        """Get volume stats.

        If 'refresh' is True, update the stats first.
        """
        if refresh or not self._stats:
            self._update_volume_stats()

        return self._stats

    def _update_volume_stats(self):
        """Retrieve stats info for NexentaStor Appliance."""
        payload = {'fields': 'bytesAvailable,bytesUsed'}
        dataset = self.nef.filesystems.get(self.nas_path, payload)
        free_capacity_gb = dataset['bytesAvailable'] // units.Gi
        allocated_capacity_gb = dataset['bytesUsed'] // units.Gi
        total_capacity_gb = free_capacity_gb + allocated_capacity_gb
        provisioned_capacity_gb = total_volumes = 0
        ctxt = context.get_admin_context()
        volumes = objects.VolumeList.get_all_by_host(ctxt, self.host)
        for volume in volumes:
            provisioned_capacity_gb += volume['size']
            total_volumes += 1
        volume_backend_name = (
            self.configuration.safe_get('volume_backend_name'))
        if not volume_backend_name:
            LOG.error('Failed to get configured volume backend name')
            volume_backend_name = '%(product)s_%(protocol)s' % {
                'product': self.product_name,
                'protocol': self.storage_protocol
            }
        description = (
            self.configuration.safe_get('nexenta_dataset_description'))
        if not description:
            description = '%(product)s %(host)s:%(path)s' % {
                'product': self.product_name,
                'host': self.configuration.nas_host,
                'path': self.configuration.nas_share_path
            }
        max_over_subscription_ratio = (
            self.configuration.safe_get('max_over_subscription_ratio'))
        reserved_percentage = (
            self.configuration.safe_get('reserved_percentage'))
        if reserved_percentage is None:
            reserved_percentage = 0
        location_info = '%(driver)s:%(host)s:%(path)s' % {
            'driver': self.driver_name,
            'host': self.configuration.nas_host,
            'path': self.configuration.nas_share_path
        }
        display_name = 'Capabilities of %(product)s %(protocol)s driver' % {
            'product': self.product_name,
            'protocol': self.storage_protocol
        }
        visibility = 'public'
        self._stats = {
            'driver_version': self.VERSION,
            'vendor_name': self.vendor_name,
            'storage_protocol': self.storage_protocol,
            'volume_backend_name': volume_backend_name,
            'location_info': location_info,
            'description': description,
            'display_name': display_name,
            'pool_name': self.nas_path.split(posixpath.sep)[0],
            'multiattach': True,
            'QoS_support': False,
            'consistencygroup_support': True,
            'consistent_group_snapshot_enabled': True,
            'online_extend_support': True,
            'sparse_copy_volume': True,
            'thin_provisioning_support': True,
            'thick_provisioning_support': True,
            'total_capacity_gb': total_capacity_gb,
            'allocated_capacity_gb': allocated_capacity_gb,
            'free_capacity_gb': free_capacity_gb,
            'provisioned_capacity_gb': provisioned_capacity_gb,
            'total_volumes': total_volumes,
            'max_over_subscription_ratio': max_over_subscription_ratio,
            'reserved_percentage': reserved_percentage,
            'visibility': visibility,
            'nef_scheme': self.nef.scheme,
            'nef_hosts': ','.join(self.nef.hosts),
            'nef_port': self.nef.port,
            'nef_url': self.nef.url()
        }
        LOG.debug('Updated volume backend statistics for host %(host)s '
                  'and volume backend %(volume_backend_name)s: %(stats)s',
                  {'host': self.host,
                   'volume_backend_name': volume_backend_name,
                   'stats': self._stats})

    def _get_existing_volume(self, existing_ref):
        types = {
            'source-name': 'path',
            'source-guid': 'guid'
        }
        if not any(key in types for key in existing_ref):
            keys = ', '.join(types.keys())
            message = (_('Manage existing volume failed '
                         'due to invalid backend reference. '
                         'Volume reference must contain '
                         'at least one valid key: %(keys)s')
                       % {'keys': keys})
            raise jsonrpc.NefException(code='EINVAL', message=message)
        payload = {
            'parent': self.nas_path,
            'fields': 'path',
            'recursive': False
        }
        for key, value in types.items():
            if key in existing_ref:
                if value == 'path':
                    path = posixpath.join(self.nas_path,
                                          existing_ref[key])
                else:
                    path = existing_ref[key]
                payload[value] = path
        existing_volumes = self.nef.filesystems.list(payload)
        if len(existing_volumes) == 1:
            volume_path = existing_volumes[0]['path']
            volume_name = posixpath.basename(volume_path)
            existing_volume = {
                'name': volume_name,
                'path': volume_path
            }
            vid = utils.extract_id_from_volume_name(volume_name)
            if utils.check_already_managed_volume(vid):
                message = (_('Volume %(name)s already managed')
                           % {'name': volume_name})
                raise jsonrpc.NefException(code='EBUSY', message=message)
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
        ctxt = context.get_admin_context()
        return objects.Snapshot.exists(ctxt, snapshot_id)

    def _get_existing_snapshot(self, snapshot, existing_ref):
        types = {
            'source-name': 'name',
            'source-guid': 'guid'
        }
        if not any(key in types for key in existing_ref):
            keys = ', '.join(types.keys())
            message = (_('Manage existing snapshot failed '
                         'due to invalid backend reference. '
                         'Snapshot reference must contain '
                         'at least one valid key: %(keys)s')
                       % {'keys': keys})
            raise jsonrpc.NefException(code='EINVAL', message=message)
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
            sid = utils.extract_id_from_snapshot_name(name)
            if self._check_already_managed_snapshot(sid):
                message = (_('Snapshot %(name)s already managed')
                           % {'name': name})
                raise jsonrpc.NefException(code='EBUSY', message=message)
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

    @coordination.synchronized('{self.nef.lock}')
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
        if existing_volume['name'] != volume['name']:
            volume_path = self._get_volume_path(volume)
            payload = {'newPath': volume_path}
            self.nef.filesystems.rename(existing_volume_path, payload)

    def manage_existing_get_size(self, volume, existing_ref):
        """Return size of volume to be managed by manage_existing.

        When calculating the size, round up to the next GB.

        :param volume:       Cinder volume to manage
        :param existing_ref: Driver-specific information used to identify a
                             volume
        :returns size:       Volume size in GiB (integer)
        """
        existing_volume = self._get_existing_volume(existing_ref)
        self._set_volume_acl(existing_volume)
        nfs_share, mount_point, volume_file = self._mount_volume(existing_volume)
        try:
            volume_info = image_utils.qemu_img_info(volume_file,
                                                    run_as_root=True,
                                                    force_share=True)
        except OSError as error:
            code = errno.errorcode[error.errno]
            message = (_('Manage existing volume %(volume)s failed: '
                         'unable to get size of volume backend file '
                         '%(volume_file)s: %(error)s')
                       % {'volume': existing_volume['name'],
                          'volume_file': volume_file,
                          'error': error.strerror})
            raise jsonrpc.NefException(code=code, message=message)
        finally:
            self._unmount_volume(existing_volume, nfs_share, mount_point)
        return volume_info.virtual_size // units.Gi

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
            'parent': self.nas_path,
            'fields': 'guid,parent,path,bytesUsed',
            'recursive': False
        }
        volumes = self.nef.filesystems.list(payload)
        for volume in volumes:
            safe_to_manage = True
            reason_not_safe = None
            cinder_id = None
            extra_info = None
            path = volume['path']
            guid = volume['guid']
            parent = volume['parent']
            size = volume['bytesUsed'] // units.Gi
            name = posixpath.basename(path)
            if path == self.nas_path:
                continue
            if parent != self.nas_path:
                continue
            if name in cinder_volume_names:
                cinder_id = cinder_volume_names[name]
                safe_to_manage = False
                reason_not_safe = _('Volume already managed')
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
        return utils.paginate_entries_list(manageable_volumes,
                                           marker, limit, offset,
                                           sort_keys, sort_dirs)

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

    @coordination.synchronized('{self.nef.lock}')
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
        manageable_snapshots = []
        cinder_volume_names = {}
        cinder_snapshot_names = {}
        ctxt = context.get_admin_context()
        cinder_volumes = objects.VolumeList.get_all_by_host(ctxt, self.host)
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
            'parent': self.nas_path,
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
            if name.startswith(self.origin_snapshot_template):
                LOG.debug('Skip temporary origin snapshot %(path)s',
                          {'path': path})
                continue
            if name.startswith(self.group_snapshot_template):
                LOG.debug('Skip temporary group snapshot %(path)s',
                          {'path': path})
                continue
            if snapshot['hprService'] or snapshot['snaplistId']:
                LOG.debug('Skip HPR/snapping snapshot %(path)s',
                          {'path': path})
                continue
            if name in cinder_snapshot_names:
                size = cinder_snapshot_names[name]['size']
                cinder_id = cinder_snapshot_names[name]['id']
                safe_to_manage = False
                reason_not_safe = _('Snapshot already managed')
            else:
                size = cinder_volume_names[parent]['size']
                payload = {'fields': 'clones'}
                props = self.nef.snapshots.get(path)
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
        return utils.paginate_entries_list(manageable_snapshots,
                                           marker, limit, offset,
                                           sort_keys, sort_dirs)

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

    def update_migrated_volume(self, context, volume, new_volume,
                               original_volume_status):
        """Return model update for migrated volume.

        This method should rename the back-end volume name on the
        destination host back to its original name on the source host.

        :param context: The context of the caller
        :param volume: The original volume that was migrated to this backend
        :param new_volume: The migration volume object that was created on
                           this backend as part of the migration process
        :param original_volume_status: The status of the original volume
        :returns: model_update to update DB with any needed changes
        """
        name_id = None
        provider_location = None
        volume_renamed = False
        volume_path = self._get_volume_path(volume)
        new_volume_path = self._get_volume_path(new_volume)
        backup_volume_path = '%s-backup' % volume_path
        if volume['host'] == new_volume['host']:
            payload = {'newPath': backup_volume_path}
            try:
                self.nef.filesystems.rename(volume_path, payload)
            except jsonrpc.NefException as error:
                LOG.error('Failed to create backup copy of volume '
                          '%(volume)s: %(error)s',
                          {'volume': volume['name'],
                           'error': error})
                if error.code != 'ENOENT':
                    raise error
            else:
                volume_renamed = True

        payload = {'newPath': volume_path}
        try:
            self.nef.filesystems.rename(new_volume_path, payload)
        except jsonrpc.NefException as rename_error:
            LOG.error('Failed to rename temporary volume %(new_volume)s '
                      'to original %(volume)s after migration: %(error)s',
                      {'new_volume': new_volume['name'],
                       'volume': volume['name'],
                       'error': rename_error})
            if volume_renamed:
                payload = {'newPath': volume_path}
                try:
                    self.nef.filesystems.rename(backup_volume_path, payload)
                except jsonrpc.NefException as restore_error:
                    LOG.error('Failed to restore backup copy of volume '
                              '%(volume)s: %(error)s',
                              {'volume': volume['name'],
                               'error': restore_error})
            raise rename_error
        if volume_renamed:
            payload = {'force': True}
            try:
                self.nef.filesystems.delete(backup_volume_path, payload)
            except jsonrpc.NefException as error:
                LOG.error('Failed to delete backup copy of volume '
                          '%(volume)s: %(error)s',
                          {'volume': volume['name'],
                           'error': error})
        if volume['host'] == new_volume['host']:
            name_id = new_volume['id']
        model_update = {
            '_name_id': name_id,
            'provider_location': provider_location
        }
        return model_update

    def before_volume_copy(self, ctxt, src_volume, dst_volume, remote=None):
        """Driver-specific actions before copy volume data.

        This method will be called before _copy_volume_data during volume
        migration
        """
        LOG.debug(' ===> before_volume_copy %s => %s on %s', src_volume['name'], dst_volume['name'], self.host)
        src_nfs_share, src_mount_point, src_volume_file = (
            self._mount_volume(src_volume))
        src_volume_info = image_utils.qemu_img_info(src_volume_file,
                                                    run_as_root=True,
                                                    force_share=True)
        self._unmount_volume(src_volume, src_nfs_share, src_mount_point)
        dst_nfs_share, dst_mount_point, dst_volume_file = (
            self._mount_volume(dst_volume))
        dst_volume_info = image_utils.qemu_img_info(dst_volume_file,
                                                    run_as_root=True,
                                                    force_share=True)
        if src_volume_info.file_format == dst_volume_info.file_format:
            self._unmount_volume(dst_volume, dst_nfs_share, dst_mount_point)
            return
        tmp_volume_file = '%(path)s.%(format)s' % {
            'path': dst_volume_file,
            'format': src_volume_info.file_format
        }
        self._execute('qemu-img', 'convert',
                      '-f', dst_volume_info.file_format,
                      '-O', src_volume_info.file_format,
                      dst_volume_file, tmp_volume_file,
                      run_as_root=True)
        self._execute('rm', '-f', dst_volume_file, run_as_root=True)
        self._execute('mv', tmp_volume_file, dst_volume_file, run_as_root=True)
        self._unmount_volume(dst_volume, dst_nfs_share, dst_mount_point)

    def after_volume_copy(self, ctxt, src_volume, dst_volume, remote=None):
        """Driver-specific actions after copy volume data.

        This method will be called after _copy_volume_data during volume
        migration
        """
        LOG.debug(' ===> after_volume_copy %s => %s on %s', src_volume['name'], dst_volume['name'], self.host)
        properties = self.nef.filesystems.properties
        payload = self._get_vendor_properties(dst_volume, properties)
        dst_volume_format = payload.pop('volumeFormat')
        dst_nfs_share, dst_mount_point, dst_volume_file = (
            self._mount_volume(dst_volume))
        dst_volume_info = image_utils.qemu_img_info(dst_volume_file,
                                                    run_as_root=True,
                                                    force_share=True)
        if dst_volume_info.file_format == dst_volume_format:
            self._unmount_volume(dst_volume, dst_nfs_share, dst_mount_point)
            return
        tmp_volume_file = '%(path)s.%(format)s' % {
            'path': dst_volume_file,
            'format': dst_volume_format
        }
        self._execute('qemu-img', 'convert',
                      '-f', dst_volume_info.file_format,
                      '-O', dst_volume_format,
                      dst_volume_file, tmp_volume_file,
                      run_as_root=True)
        self._execute('rm', '-f', dst_volume_file, run_as_root=True)
        self._execute('mv', tmp_volume_file, dst_volume_file, run_as_root=True)
        self._unmount_volume(dst_volume, dst_nfs_share, dst_mount_point)

    def retype(self, context, volume, new_type, diff, host):
        """Retype from one volume type to another."""
        LOG.debug('Retype volume %(volume)s to host %(host)s '
                  'and volume type %(type)s with diff %(diff)s',
                  {'volume': volume['name'], 'host': host['host'],
                   'type': new_type['name'], 'diff': diff})
        migrated = retyped = False
        model_update = None
        #if volume['host'] != host['host']:
        #    # TODO
        #    migrated, model_update = self.migrate_volume(context, volume, host)
        volume_path = self._get_volume_path(volume)
        payload = {'source': True}
        volume_specs = self.nef.filesystems.get(volume_path, payload)
        payload = {}
        extra_specs = volume_types.get_volume_type_extra_specs(new_type['id'])
        vendor_specs = self.nef.filesystems.properties
        for vendor_spec in vendor_specs:
            property_name = vendor_spec['name']
            api = vendor_spec['api']
            if 'retype' in vendor_spec:
                LOG.error('Failed to retype vendor volume property '
                          '%(property_name)s. %(reason)s',
                          {'property_name': property_name,
                           'reason': vendor_spec['retype']})
                return retyped
            if property_name in extra_specs:
                extra_spec = extra_specs[property_name]
                value = self._get_vendor_value(extra_spec, vendor_spec)
                payload[api] = value
            elif (api in volume_specs and 'source' in volume_specs and
                  api in volume_specs['source'] and
                  volume_specs['source'][api] in ['local', 'received']):
                if 'cfg' in vendor_spec:
                    cfg = vendor_spec['cfg']
                    value = self.configuration.safe_get(cfg)
                    if volume_specs[api] != value:
                        payload[api] = value
                else:
                    if 'inherit' in vendor_spec:
                        LOG.debug('Skip inherit vendor volume property '
                                  '%(property_name)s. %(reason)s',
                                  {'property_name': property_name,
                                   'reason': vendor_spec['inherit']})
                        continue
                    payload[api] = None
        try:
            self.nef.filesystems.set(volume_path, payload)
            retyped = True
        except jsonrpc.NefException as error:
            LOG.error('Failed to retype volume %(volume)s: %(error)s',
                      {'volume': volume['name'], 'error': error})
        return retyped or migrated, model_update

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
        properties = {}
        namespace = self.nef.filesystems.namespace
        vendor_properties = self.nef.filesystems.properties
        keys = ['enum', 'default', 'minimum', 'maximum']
        for vendor_spec in vendor_properties:
            property_spec = {}
            for key in keys:
                if key in vendor_spec:
                    property_spec[key] = vendor_spec[key]
            if 'api' in vendor_spec:
                api = vendor_spec['api']
                if api in self.root:
                    property_spec['default'] = self.root[api]
            property_name = vendor_spec['name']
            property_title = vendor_spec['title']
            property_description = vendor_spec['description']
            property_type = vendor_spec['type']
            LOG.debug('Set %(product_name)s %(storage_protocol)s backend '
                      '%(property_type)s property %(property_name)s: '
                      '%(property_spec)s',
                      {'product_name': self.product_name,
                       'storage_protocol': self.storage_protocol,
                       'property_type': property_type,
                       'property_name': property_name,
                       'property_spec': property_spec})
            self._set_property(
                properties,
                property_name,
                property_title,
                property_description,
                property_type,
                **property_spec
            )
        return properties, namespace

    def _get_vendor_properties(self, volume, vendor_specs):
        properties = {}
        extra_specs = {}
        type_id = volume.get('volume_type_id', None)
        if type_id:
            extra_specs = volume_types.get_volume_type_extra_specs(type_id)
        for vendor_spec in vendor_specs:
            property_name = vendor_spec['name']
            if property_name in extra_specs:
                extra_spec = extra_specs[property_name]
                value = self._get_vendor_value(extra_spec, vendor_spec)
            elif 'cfg' in vendor_spec:
                cfg = vendor_spec['cfg']
                value = self.configuration.safe_get(cfg)
            else:
                continue
            api = vendor_spec['api']
            properties[api] = value
            LOG.debug('Get vendor property name %(property_name)s '
                      'with API name %(api)s and %(type)s value '
                      '%(value)s for volume %(volume)s',
                      {'property_name': property_name,
                       'api': api,
                       'type': type(value).__name__,
                       'value': value,
                       'volume': volume['name']})
        return properties

    def _get_vendor_value(self, value, vendor_spec):
        name = vendor_spec['name']
        code = 'EINVAL'
        if vendor_spec['type'] == 'integer':
            try:
                value = int(value)
            except ValueError:
                message = (_('Invalid non-integer value %(value)s for '
                             'vendor property name %(name)s')
                           % {'value': value, 'name': name})
                raise jsonrpc.NefException(code=code, message=message)
            if 'minimum' in vendor_spec:
                minimum = vendor_spec['minimum']
                if value < minimum:
                    message = (_('Integer value %(value)s is less than '
                                 'allowed minimum %(minimum)s for vendor '
                                 'property name %(name)s')
                               % {'value': value, 'minimum': minimum,
                                  'name': name})
                    raise jsonrpc.NefException(code=code, message=message)
            if 'maximum' in vendor_spec:
                maximum = vendor_spec['maximum']
                if value > maximum:
                    message = (_('Integer value %(value)s is greater than '
                                 'allowed maximum %(maximum)s for vendor '
                                 'property name %(name)s')
                               % {'value': value, 'maximum': maximum,
                                  'name': name})
                    raise jsonrpc.NefException(code=code, message=message)
        elif vendor_spec['type'] == 'string':
            try:
                value = str(value)
            except UnicodeEncodeError:
                message = (_('Invalid non-ASCII value %(value)s for vendor '
                             'property name %(name)s')
                           % {'value': value, 'name': name})
                raise jsonrpc.NefException(code=code, message=message)
        elif vendor_spec['type'] == 'boolean':
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
        if 'enum' in vendor_spec:
            enum = vendor_spec['enum']
            if value not in enum:
                message = (_('Value %(value)s is out of allowed enumeration '
                             '%(enum)s for vendor property name %(name)s')
                           % {'value': value, 'enum': enum, 'name': name})
                raise jsonrpc.NefException(code=code, message=message)
        return value

    def _get_host_addresses(self):
        """Return NexentaStor IP addresses list."""
        addresses = []
        items = self.nef.netaddrs.list()
        for item in items:
            cidr = six.text_type(item['address'])
            addr, mask = cidr.split('/')
            obj = ipaddress.ip_address(addr)
            if not obj.is_loopback:
                addresses.append(obj.exploded)
        LOG.debug('Configured IP addresses: %(addresses)s',
                  {'addresses': addresses})
        return addresses
