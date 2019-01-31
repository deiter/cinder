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

import hashlib
import os

from oslo_log import log as logging
from oslo_utils import units

from cinder import coordination
from cinder import interface
from cinder.i18n import _
import cinder.privsep.fs
from cinder.volume.drivers import nfs
from cinder.volume.drivers.nexenta import options
from cinder.volume.drivers.nexenta.ns5.jsonrpc import NefProxy
from cinder.volume.drivers.nexenta.ns5.jsonrpc import NefException

VERSION = '1.8.0'
LOG = logging.getLogger(__name__)


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
    """

    driver_prefix = 'nexenta'
    volume_backend_name = 'NexentaNfsDriver'
    VERSION = VERSION

    # ThirdPartySystems wiki page
    CI_WIKI_NAME = "Nexenta_CI"

    def __init__(self, *args, **kwargs):
        super(NexentaNfsDriver, self).__init__(*args, **kwargs)
        if self.configuration:
            self.configuration.append_config_values(
                options.NEXENTA_CONNECTION_OPTS)
            self.configuration.append_config_values(
                options.NEXENTA_NFS_OPTS)
            self.configuration.append_config_values(
                options.NEXENTA_DATASET_OPTS)
        self.nef = None
        self.root_mount_point = None
        self.nas_host = self.configuration.nas_host
        self.root_path = self.configuration.nas_share_path
        self.pool = self.root_path.split('/')[0]
        self.configuration.nexenta_volume = self.pool
        self.dataset_sparsed = self.configuration.nexenta_sparse
        self.dataset_deduplication = self.configuration.nexenta_dataset_dedup
        self.dataset_compression = (
            self.configuration.nexenta_dataset_compression)
        self.dataset_description = (
            self.configuration.nexenta_dataset_description)
        self.mount_point_base = self.configuration.nexenta_mount_point_base
        self.lock = '%s:%s' % (self.backend_name, self.root_path)

    @property
    def backend_name(self):
        backend_name = None
        if self.configuration:
            backend_name = self.configuration.safe_get('volume_backend_name')
        if not backend_name:
            backend_name = self.__class__.__name__
        return backend_name

    def do_setup(self, context):
        self.nef = NefProxy(self.configuration)

    def check_for_setup_error(self):
        """Check ZFS pool, filesystem and NFS server service."""
        self.nef.pools.get(self.pool)
        filesystem = self.nef.filesystems.get(self.root_path)
        if filesystem['mountPoint'] == 'none':
            message = (_('NFS root filesystem %(path)s is not writable')
                       % {'path': filesystem['mountPoint']})
            raise NefException({'code': 'ENOENT', 'message': message})
        if not filesystem['isMounted']:
            message = (_('NFS root filesystem %(path)s is not mounted')
                       % {'path': filesystem['mountPoint']})
            raise NefException({'code': 'ENOTDIR', 'message': message})
        if filesystem['nonBlockingMandatoryMode']:
            payload = {'nonBlockingMandatoryMode': False}
            self.nef.filesystems.set(self.root_path, payload)
        self.root_mount_point = filesystem['mountPoint']
        service = self.nef.services.get('nfs')
        if service['state'] != 'online':
            message = (_('NFS server service is not online: %(state)s')
                       % {'state': service['state']})
            raise NefException({'code': 'ESRCH', 'message': message})
        share = self.nef.nfs.get(self.root_path)
        if share['shareState'] != 'online':
            message = (_('NFS share %(share)s is not online: %(state)s')
                       % {'share': self.root_path,
                          'state': share['shareState']})
            raise NefException({'code': 'ESRCH', 'message': message})

    def create_volume(self, volume):
        """Creates a volume.

        :param volume: volume reference
        """
        volume_path = self._get_volume_path(volume)
        payload = {'path': volume_path, 'compressionMode': 'off'}
        self.nef.filesystems.create(payload)
        try:
            self._set_volume_acl(volume)
            self._mount_volume(volume)
            volume_file = self.local_path(volume)
            if self.dataset_sparsed:
                self._create_sparsed_file(volume_file, volume['size'])
            else:
                self._create_regular_file(volume_file, volume['size'])
                if self.dataset_compression != 'off':
                    payload = {'compressionMode': self.dataset_compression}
                    self.nef.filesystems.set(volume_path, payload)
        except NefException as create_error:
            try:
                payload = {'force': True}
                self.nef.filesystems.delete(volume_path, payload)
            except NefException as delete_error:
                LOG.debug('Failed to delete volume %(path)s: %(error)s',
                          {'path': volume_path, 'error': delete_error})
            raise create_error
        finally:
            self._unmount_volume(volume)

    def copy_image_to_volume(self, context, volume, image_service, image_id):
        LOG.debug('Copy image %(image)s to volume %(volume)s',
                  {'image': image_id, 'volume': volume['name']})
        self._mount_volume(volume)
        super(NexentaNfsDriver, self).copy_image_to_volume(
            context, volume, image_service, image_id)
        self._unmount_volume(volume)

    def copy_volume_to_image(self, context, volume, image_service, image_meta):
        LOG.debug('Copy volume %(volume)s to image %(image)s',
                  {'volume': volume['name'], 'image': image_meta['id']})
        self._mount_volume(volume)
        super(NexentaNfsDriver, self).copy_volume_to_image(
            context, volume, image_service, image_meta)
        self._unmount_volume(volume)

    def _ensure_share_unmounted(self, share):
        """Ensure that NFS share is unmounted on the host.

        :param share: share path
        """
        attempts = max(1, self.configuration.nfs_mount_attempts)
        path = self._get_mount_point_for_share(share)
        if path not in self._remotefsclient._read_mounts():
            LOG.debug('NFS share %(share)s is not mounted at %(path)s',
                      {'share': share, 'path': path})
            return
        for attempt in range(0, attempts):
            try:
                cinder.privsep.fs.umount(path)
                LOG.debug('NFS share %(share)s has been unmounted at %(path)s',
                          {'share': share, 'path': path})
                break
            except Exception as error:
                if attempt == (attempts - 1):
                    LOG.error('Failed to unmount NFS share %(share)s '
                              'after %(attempts)s attempts',
                              {'share': share, 'attempts': attempts})
                    raise error
                LOG.debug('Unmount attempt %(attempt)s failed: %(error)s, '
                          'retrying unmount %(share)s from %(path)s',
                          {'attempt': attempt, 'error': error,
                           'share': share, 'path': path})
                self.nef.delay(attempt)
        self._delete(path)

    def _mount_volume(self, volume):
        """Ensure that volume is activated and mounted on the host."""
        volume_path = self._get_volume_path(volume)
        filesystem = self.nef.filesystems.get(volume_path)
        if filesystem['mountPoint'] == 'none':
            payload = {'datasetName': volume_path}
            self.nef.hpr.activate(payload)
            filesystem = self.nef.filesystems.get(volume_path)
        elif not filesystem['isMounted']:
            self.nef.filesystems.mount(volume_path)
        share = '%s:%s' % (self.nas_host, filesystem['mountPoint'])
        self._ensure_share_mounted(share)

    def _unmount_volume(self, volume):
        """Ensure that volume is unmounted on the host."""
        share = self._get_volume_share(volume)
        self._ensure_share_unmounted(share)

    def _create_sparsed_file(self, path, size):
        """Creates file with 0 disk usage."""
        if self.configuration.nexenta_qcow2_volumes:
            self._create_qcow2_file(path, size)
        else:
            super(NexentaNfsDriver, self)._create_sparsed_file(path, size)

    def migrate_volume(self, context, volume, host):
        """Migrate if volume and host are managed by Nexenta appliance.

        :param context: context
        :param volume: a dictionary describing the volume to migrate
        :param host: a dictionary describing the host to migrate to
        """
        LOG.debug('Migrate volume %(volume)s to host %(host)s',
                  {'volume': volume['name'], 'host': host})

        false_ret = (False, None)

        if volume['status'] not in ('available', 'retyping'):
            LOG.error('Volume %(volume)s status must be available or '
                      'retyping, current volume status is %(status)s',
                      {'volume': volume['name'], 'status': volume['status']})
            return false_ret

        if 'capabilities' not in host:
            LOG.error('Unsupported host %(host)s: no capabilities found',
                      {'host': host})
            return false_ret

        capabilities = host['capabilities']

        if not ('location_info' in capabilities and
                'vendor_name' in capabilities and
                'free_capacity_gb' in capabilities):
            LOG.error('Unsupported host %(host)s: required NFS '
                      'and vendor capabilities are not found',
                      {'host': host})
            return false_ret

        driver_name = capabilities['location_info'].split(':')[0]
        dst_root = capabilities['location_info'].split(':/')[1]

        if not (capabilities['vendor_name'] == 'Nexenta' and
                driver_name == self.__class__.__name__):
            LOG.error('Unsupported host %(host)s: incompatible '
                      'vendor %(vendor)s or driver %(driver)s',
                      {'host': host,
                       'vendor': capabilities['vendor_name'],
                       'driver': driver_name})
            return false_ret

        if capabilities['free_capacity_gb'] < volume['size']:
            LOG.error('There is not enough space available on the '
                      'host %(host)s to migrate volume %(volume), '
                      'free space: %(free)d, required: %(size)d',
                      {'host': host, 'volume': volume['name'],
                       'free': capabilities['free_capacity_gb'],
                       'size': volume['size']})
            return false_ret

        src_path = self._get_volume_path(volume)
        dst_path = '%s/%s' % (dst_root, volume['name'])
        nef_ips = capabilities['nef_url'].split(',')
        nef_ips.append(None)
        svc = 'cinder-migrate-%s' % volume['name']
        for nef_ip in nef_ips:
            payload = {'name': svc,
                       'sourceDataset': src_path,
                       'destinationDataset': dst_path,
                       'type': 'scheduled',
                       'sendShareNfs': True}
            if nef_ip is not None:
                payload['isSource'] = True
                payload['remoteNode'] = {
                    'host': nef_ip,
                    'port': capabilities['nef_port']
                }
            try:
                self.nef.hpr.create(payload)
                break
            except NefException as error:
                if nef_ip is None or error.code not in ('EINVAL', 'ENOENT'):
                    LOG.error('Failed to create replication '
                              'service %(payload)s: %(error)s',
                              {'payload': payload, 'error': error})
                    return false_ret

        try:
            self.nef.hpr.start(svc)
        except NefException as error:
            LOG.error('Failed to start replication '
                      'service %(svc)s: %(error)s',
                      {'svc': svc, 'error': error})
            try:
                payload = {'force': True}
                self.nef.hpr.delete(svc, payload)
            except NefException as error:
                LOG.error('Failed to delete replication '
                          'service %(svc)s: %(error)s',
                          {'svc': svc, 'error': error})
            return false_ret

        payload = {'destroySourceSnapshots': True,
                   'destroyDestinationSnapshots': True}
        progress = True
        retry = 0
        while progress:
            retry += 1
            hpr = self.nef.hpr.get(svc)
            state = hpr['state']
            if state == 'disabled':
                progress = False
            elif state == 'enabled':
                self.nef.delay(retry)
            else:
                self.nef.hpr.delete(svc, payload)
                return false_ret
        self.nef.hpr.delete(svc, payload)

        try:
            self.delete_volume(volume)
        except NefException as error:
            LOG.debug('Failed to delete source volume %(volume)s: %(error)s',
                      {'volume': volume['name'], 'error': error})
        return True, None

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
        LOG.debug('Initialize volume connection for %(volume)s',
                  {'volume': volume['name']})
        share = self._get_volume_share(volume)
        return {
            'driver_volume_type': self.driver_volume_type,
            'mount_point_base': self.mount_point_base,
            'data': {
                'export': share,
                'name': 'volume'
            }
        }

    def ensure_export(self, context, volume):
        """Synchronously recreate an export for a volume."""
        pass

    @coordination.synchronized('{self.lock}')
    def delete_volume(self, volume):
        """Deletes a volume.

        :param volume: volume reference
        """
        volume_path = self._get_volume_path(volume)
        self._unmount_volume(volume)
        delete_payload = {'force': True, 'snapshots': True}
        try:
            self.nef.filesystems.delete(volume_path, delete_payload)
        except NefException as error:
            if error.code != 'EEXIST':
                raise error
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
            LOG.debug('Failed to remove mountpoint %(path)s: %(error)s',
                      {'path': path, 'error': error.strerror})

    def extend_volume(self, volume, new_size):
        """Extend an existing volume.

        :param volume: volume reference
        :param new_size: volume new size in GB
        """
        LOG.info('Extend volume %(volume)s, new size: %(size)sGB',
                 {'volume': volume['name'], 'size': new_size})
        self._mount_volume(volume)
        volume_file = self.local_path(volume)
        if self.dataset_sparsed:
            self._execute('truncate', '-s',
                          '%sG' % new_size,
                          volume_file,
                          run_as_root=True)
        else:
            seek = volume['size'] * units.Ki
            count = (new_size - volume['size']) * units.Ki
            self._execute('dd',
                          'if=/dev/zero',
                          'of=%s' % volume_file,
                          'bs=%d' % units.Mi,
                          'seek=%d' % seek,
                          'count=%d' % count,
                          run_as_root=True)
        self._unmount_volume(volume)

    @coordination.synchronized('{self.lock}')
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
        self._delete_snapshot(snapshot_path)

    @coordination.synchronized('{self.lock}')
    def _delete_snapshot(self, snapshot_path, recursive=False, defer=True):
        """Deletes a snapshot.

        :param path: absolute snapshot path
        :param recursive: boolean, True to recursively destroy snapshots
                          of the same name on a child datasets
        :param defer: boolean, True to mark the snapshot for deferred
                      destroy when there are not any active references
                      to it (for example, clones)
        """
        payload = {'recursive': recursive, 'defer': defer}
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

    @coordination.synchronized('{self.lock}')
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
        self.nef.filesystems.unmount(clone_path)
        self.nef.filesystems.mount(clone_path)
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
        snapshot_name = self._get_clone_snapshot_name(volume)
        snapshot = {'name': snapshot_name,
                    'volume_id': src_vref['id'],
                    'volume_name': src_vref['name'],
                    'volume_size': src_vref['size']}
        self.create_snapshot(snapshot)
        try:
            return self.create_volume_from_snapshot(volume, snapshot)
        except NefException as volume_error:
            LOG.debug('Failed to create cloned volume: '
                      '%(error)s. Delete temporary snapshot '
                      '%(volume)s@%(snapshot)s',
                      {'error': volume_error,
                       'volume': snapshot['volume_name'],
                       'snapshot': snapshot['name']})
            try:
                self.delete_snapshot(snapshot)
            except NefException as snapshot_error:
                LOG.debug('Failed to delete temporary snapshot '
                          '%(volume)s@%(snapshot)s: %(error)s',
                          {'volume': snapshot['volume_name'],
                           'snapshot': snapshot['name'],
                           'error': snapshot_error})
            raise volume_error
        snapshot_path = self._get_snapshot_path(snapshot)
        self._delete_snapshot(snapshot_path)

    def create_consistencygroup(self, context, group):
        """Creates a consistencygroup.

        :param context: the context of the caller.
        :param group: the dictionary of the consistency group to be created.
        :returns: group_model_update
        """
        group_model_update = {}
        return group_model_update

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

    def update_consistencygroup(self, context, group,
                                add_volumes=None,
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

    @coordination.synchronized('{self.lock}')
    def _rename_cgsnapshot(self, cgsnapshot, snapshot):
        path = '%s/%s@%s' % (self.root_path, snapshot['volume_name'],
                             self._get_cgsnapshot_name(cgsnapshot))
        payload = {'newName': snapshot['name']}
        self.nef.snapshots.rename(path, payload)

    def create_cgsnapshot(self, context, cgsnapshot, snapshots):
        """Creates a consistency group snapshot.

        :param context: the context of the caller.
        :param cgsnapshot: the dictionary of the cgsnapshot to be created.
        :param snapshots: a list of snapshot dictionaries in the cgsnapshot.
        :returns: group_model_update, snapshots_model_update
        """
        group_model_update = {}
        snapshots_model_update = []
        path = self._get_cgsnapshot_path(cgsnapshot)
        payload = {'path': path, 'recursive': True}
        self.nef.snapshots.create(payload)
        for snapshot in snapshots:
            self._rename_cgsnapshot(cgsnapshot, snapshot)
        self._delete_snapshot(path, True)
        return group_model_update, snapshots_model_update

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
            path = self._get_cgsnapshot_path(group)
            payload = {'path': path, 'recursive': True}
            self.nef.snapshots.create(payload)
            for volume, source_vol in zip(volumes, source_vols):
                snapshot_name = self._get_clone_snapshot_name(volume)
                snapshot = {'name': snapshot_name,
                            'volume_id': source_vol['id'],
                            'volume_name': source_vol['name'],
                            'volume_size': source_vol['size']}
                self._rename_cgsnapshot(group, snapshot)
                self.create_volume_from_snapshot(volume, snapshot)
            self._delete_snapshot(path, True)
        return group_model_update, volumes_model_update

    def _local_volume_dir(self, volume):
        """Get volume dir (mounted locally fs path) for given volume.

        :param volume: volume reference
        """
        share = self._get_volume_share(volume)
        path = hashlib.md5(share).hexdigest()
        return os.path.join(self.mount_point_base, path)

    def local_path(self, volume):
        """Get volume path (mounted locally fs path) for given volume.

        :param volume: volume reference
        """
        volume_dir = self._local_volume_dir(volume)
        return os.path.join(volume_dir, 'volume')

    def _set_volume_acl(self, volume):
        """Sets access permissions for given volume.

        :param volume: volume reference
        """
        volume_path = self._get_volume_path(volume)
        payload = {
            "type": "allow",
            "principal": "everyone@",
            "permissions": [
                "list_directory",
                "read_data",
                "add_file",
                "write_data",
                "add_subdirectory",
                "append_data",
                "read_xattr",
                "write_xattr",
                "execute",
                "delete_child",
                "read_attributes",
                "write_attributes",
                "delete",
                "read_acl",
                "write_acl",
                "write_owner",
                "synchronize"
            ],
            "flags": [
                "file_inherit",
                "dir_inherit"
            ]
        }
        self.nef.filesystems.acl(volume_path, payload)

    def _get_volume_share(self, volume):
        """Return NFS share path for the volume."""
        return '%s:%s/%s' % (self.nas_host,
                             self.root_mount_point,
                             volume['name'])

    def _get_volume_path(self, volume):
        """Return ZFS dataset path for the volume."""
        return '%s/%s' % (self.root_path, volume['name'])

    def _get_snapshot_path(self, snapshot):
        """Return ZFS snapshot path for the snapshot."""
        return '%s/%s@%s' % (self.root_path,
                             snapshot['volume_name'],
                             snapshot['name'])

    def _get_cgsnapshot_path(self, cgsnapshot):
        """Return ZFS snapshot path for the consistency group snapshot."""
        snapshot_name = self._get_cgsnapshot_name(cgsnapshot)
        return '%s@%s' % (self.root_path, snapshot_name)

    @staticmethod
    def _get_clone_snapshot_name(volume):
        """Return snapshot name that will be used to clone the volume."""
        return 'cinder-clone-snapshot-%s' % volume['id']

    @staticmethod
    def _get_cgsnapshot_name(cgsnapshot):
        """Return cgsnapshot name for the consistency group snapshot."""
        return 'cgsnapshot-%s' % cgsnapshot['id']

    def get_volume_stats(self, refresh=False):
        """Get volume stats.

        If 'refresh' is True, update the stats first.
        """
        if refresh or not self._stats:
            self._update_volume_stats()

        return self._stats

    def _update_volume_stats(self):
        """Retrieve stats info for NexentaStor Appliance."""
        LOG.debug('Updating volume stats')
        payload = {'fields': 'bytesAvailable,bytesUsed'}
        stats = self.nef.filesystems.get(self.root_path, payload)
        free = stats['bytesAvailable'] // units.Gi
        allocated = stats['bytesUsed'] // units.Gi
        share = '%s:%s' % (self.nas_host, self.root_mount_point)
        location_info = '%(driver)s:%(share)s' % {
            'driver': self.__class__.__name__,
            'share': share
        }
        self._stats = {
            'vendor_name': 'Nexenta',
            'dedup': self.dataset_deduplication,
            'compression': self.dataset_compression,
            'description': self.dataset_description,
            'nef_url': self.nef.host,
            'nef_port': self.nef.port,
            'driver_version': self.VERSION,
            'storage_protocol': 'NFS',
            'sparsed_volumes': self.dataset_sparsed,
            'total_capacity_gb': free + allocated,
            'free_capacity_gb': free,
            'reserved_percentage': self.configuration.reserved_percentage,
            'QoS_support': False,
            'consistencygroup_support': True,
            'consistent_group_snapshot_enabled': True,
            'multiattach': True,
            'location_info': location_info,
            'volume_backend_name': self.backend_name,
            'nfs_mount_point_base': self.mount_point_base
        }
