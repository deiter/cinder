# Copyright (c) 2016 DataDirect Networks, Inc.
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

import binascii
import errno
import os
import stat
import tempfile

from castellan import key_manager
from os_brick.remotefs import remotefs as remotefs_brick
from oslo_concurrency import processutils
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import units

from cinder import coordination
from cinder import exception
from cinder.i18n import _
from cinder.image import image_utils
from cinder import interface
from cinder.privsep import fs
from cinder import utils
from cinder.volume.drivers import remotefs
from cinder.volume import volume_utils

LOG = logging.getLogger(__name__)


lustre_opts = [
    cfg.StrOpt('lustre_share_host',
               default='',
               help='MGS NID of Lustre system, like "1.2.3.4@tcp".'),
    cfg.StrOpt('lustre_share_path',
               default='',
               help='Path to the Lustre filesystem/subdirectory.'),
    cfg.StrOpt('lustre_shares_config',
               default='/etc/cinder/lustre_shares',
               help='File with the list of available Lustre shares.'),
    cfg.StrOpt('lustre_mount_point_base',
               default='$state_path/mnt',
               help='Base dir containing mount points for Lustre shares.'),
    cfg.StrOpt('lustre_mount_options',
               default='flock',
               help='Comma-separated string of Lustre mount options.'),
    cfg.BoolOpt('lustre_sparsed_volumes',
                default=True,
                help='Create volumes as sparsed files which take no space. '
                     'If set to False volume is created as regular file. '
                     'In such case volume creation takes a lot of time.'),
    cfg.BoolOpt('lustre_qcow2_volumes',
                default=False,
                help='Create volumes as qcow2 files rather than raw files.')
]

CONF = cfg.CONF
CONF.register_opts(lustre_opts)


class LustreException(exception.RemoteFSException):
    message = _("Unknown Lustre exception")


class LustreNoSuitableShareFound(exception.RemoteFSNoSuitableShareFound):
    message = _("There is no share which can host %(volume_size)sG")


class LustreNoSharesMounted(exception.RemoteFSNoSharesMounted):
    message = _("No mounted Lustre shares found")


@interface.volumedriver
class LustreDriver(remotefs.RevertToSnapshotMixin,
                   remotefs.RemoteFSManageableVolumesMixin,
                   remotefs.RemoteFSSnapDriverDistributed):
    """Lustre based cinder driver.

    Creates file on Lustre share for using it as block device on hypervisor.

    Operations such as create/delete/extend volume/snapshot use locking on a
    per-process basis to prevent multiple threads from modifying qcow2 chains
    or the snapshot .info file simultaneously.
    """

    driver_volume_type = 'lustre'
    driver_prefix = 'lustre'
    volume_backend_name = 'Lustre'
    VERSION = '1.0.0'
    CI_WIKI_NAME = "Lustre_CI"

    def __init__(self, execute=processutils.execute, *args, **kwargs):
        self._remotefsclient = None
        super(LustreDriver, self).__init__(*args, **kwargs)
        root_helper = utils.get_root_helper()
        self.configuration.append_config_values(lustre_opts)
        self.configuration.nas_host = getattr(self.configuration,
                                              'lustre_share_host',
                                              CONF.lustre_share_host)
        self.configuration.nas_share_path = getattr(self.configuration,
                                                    'lustre_share_path',
                                                    CONF.lustre_share_path)
        mount_point_base = getattr(self.configuration,
                                   'lustre_mount_point_base',
                                   CONF.lustre_mount_point_base)
        mount_point_base = os.path.realpath(mount_point_base)
        mount_options = getattr(self.configuration,
                                'lustre_mount_options',
                                CONF.lustre_mount_options)
        self._remotefsclient = remotefs_brick.RemoteFsClient(
            self.driver_volume_type, root_helper, execute=execute,
            lustre_mount_point_base=mount_point_base,
            lustre_mount_options=mount_options)
        self.base = mount_point_base
        if mount_options:
            self.configuration.nas_mount_options = '-o %s' % mount_options
        self._sparse_copy_volume_data = True
        self._supports_encryption = True
        self.reserved_percentage = self.configuration.reserved_percentage
        supports_auto_mosr = kwargs.get('supports_auto_mosr', False)
        self.max_over_subscription_ratio = (
            volume_utils.get_max_over_subscription_ratio(
                self.configuration.max_over_subscription_ratio,
                supports_auto=supports_auto_mosr))

    @staticmethod
    def get_driver_options():
        return lustre_opts

    def check_for_setup_error(self):
        lustre_package = 'lustre-client'
        lustre_mount = 'mount.lustre'
        try:
            self._execute(lustre_mount, check_exit_code=False)
        except OSError as error:
            if error.errno == errno.ENOENT:
                message = (_('Required package %(lustre_package)s '
                             'is not installed: %(error_reason)s')
                           % {'lustre_package': lustre_package,
                              'error_reason': error.strerror})
                raise LustreException(message)
            raise
        self._refresh_mounts()

    def _unmount_shares(self):
        self._load_shares_config()
        for share in self.shares:
            self._do_umount(share)

    @coordination.synchronized('{self.driver_prefix}-{share}')
    def _do_umount(self, share):
        mntpoints = self._remotefsclient._read_mounts()
        mntpoint = self._get_mount_point_for_share(share)
        if mntpoint not in mntpoints:
            LOG.debug('Lustre share %(share)s is not mounted at %(mntpoint)s',
                      {'share': share, 'mntpoint': mntpoint})
            return
        try:
            fs.umount(mntpoint)
        except processutils.ProcessExecutionError as error:
            if error.exit_code in [errno.EPIPE, errno.EBUSY]:
                LOG.warning('Failed to unmount Lustre share %(share)s '
                            'mounted at %(mntpoint)s: %(error_reason)s',
                            {'share': share, 'mntpoint': mntpoint,
                             'error_reason': error.stderr})
            else:
                raise

    def _refresh_mounts(self):
        self._unmount_shares()
        self._ensure_shares_mounted()

    def _qemu_img_info(self, path, volume_name):
        return super(LustreDriver, self)._qemu_img_info_base(
            path, volume_name, self.base, force_share=True,
            run_as_root=self._execute_as_root)

    def _update_volume_stats(self):
        """Retrieve stats info from volume group."""
        super(LustreDriver, self)._update_volume_stats()
        data = self._stats
        global_capacity = data['total_capacity_gb']
        global_free = data['free_capacity_gb']
        thin_enabled = self.configuration.lustre_sparsed_volumes
        if thin_enabled:
            provisioned_capacity = self._get_provisioned_capacity()
        else:
            provisioned_capacity = round(global_capacity - global_free, 2)
        data['provisioned_capacity_gb'] = provisioned_capacity
        data['max_over_subscription_ratio'] = (
            self.configuration.max_over_subscription_ratio)
        data['reserved_percentage'] = self.reserved_percentage
        data['thin_provisioning_support'] = thin_enabled
        data['thick_provisioning_support'] = not thin_enabled
        data['multiattach'] = not self.configuration.lustre_qcow2_volumes
        data['sparse_copy_volume'] = True
        self._stats = data

    def _copy_volume_from_snapshot(self, snapshot, volume, volume_size,
                                   src_encryption_key_id=None,
                                   new_encryption_key_id=None):
        """Copy data from snapshot to destination volume.

        This is done with a qemu-img convert to raw/qcow2 from the snapshot
        qcow2.
        """
        LOG.debug('Copying snapshot: %(snapshot)s -> volume: %(volume)s, '
                  'volume size: %(volume_size)s GB',
                  {'snapshot': snapshot.id,
                   'volume': volume.id,
                   'volume_size': volume_size})
        info_path = self._local_path_volume_info(snapshot.volume)
        snap_info = self._read_info_file(info_path)
        vol_path = self._local_volume_dir(snapshot.volume)
        forward_file = snap_info[snapshot.id]
        forward_path = os.path.join(vol_path, forward_file)
        img_info = self._qemu_img_info(forward_path, snapshot.volume.name)
        path_to_snap_img = os.path.join(vol_path, img_info.backing_file)
        path_to_new_vol = self._local_path_volume(volume)
        if self.configuration.lustre_qcow2_volumes:
            volume_format = 'qcow2'
        else:
            volume_format = 'raw'
        if new_encryption_key_id is not None:
            if src_encryption_key_id is None:
                message = (_('Failed to create an encrypted %(format)s '
                             'volume %(volume)s from an unencrypted '
                             'source snapshot %(snapshot)s.')
                           % {'format': volume_format,
                              'volume': volume.id,
                              'snapshot': snapshot.id})
                LOG.error(message)
                raise LustreException(message)
            keymgr = key_manager.API(CONF)
            new_key = keymgr.get(volume.obj_context, new_encryption_key_id)
            new_passphrase = (
                binascii.hexlify(new_key.get_encoded()).decode('utf-8'))
            src_key = keymgr.get(volume.obj_context, src_encryption_key_id)
            src_passphrase = (
                binascii.hexlify(src_key.get_encoded()).decode('utf-8'))
            tmp_dir = volume_utils.image_conversion_dir()
            with tempfile.NamedTemporaryFile(prefix='luks_',
                                             dir=tmp_dir) as src_pass_file:
                with open(src_pass_file.name, 'w') as f:
                    f.write(src_passphrase)
                with tempfile.NamedTemporaryFile(prefix='luks_',
                                                 dir=tmp_dir) as new_pass_file:
                    with open(new_pass_file.name, 'w') as f:
                        f.write(new_passphrase)
                    image_utils.convert_image(
                        path_to_snap_img,
                        path_to_new_vol,
                        'luks',
                        passphrase_file=new_pass_file.name,
                        src_passphrase_file=src_pass_file.name,
                        run_as_root=self._execute_as_root)
        else:
            image_utils.convert_image(path_to_snap_img,
                                      path_to_new_vol,
                                      volume_format,
                                      run_as_root=self._execute_as_root)
        self._set_rw_permissions_for_all(path_to_new_vol)

    def ensure_export(self, ctx, volume):
        """Synchronously recreates an export for a logical volume."""
        self._ensure_share_mounted(volume.provider_location)

    def create_export(self, ctx, volume, connector):
        """Exports the volume."""
        pass

    def remove_export(self, ctx, volume):
        """Removes an export for a logical volume."""
        pass

    def validate_connector(self, connector):
        pass

    @coordination.synchronized('{self.driver_prefix}-{volume.id}')
    def initialize_connection(self, volume, connector):
        """Allow connection to connector and return connection info."""
        LOG.debug('Initializing connection to volume %(volume)s '
                  'and connector: %(connector)s',
                  {'volume': volume.id, 'connector': connector})
        volume_dir = self._local_volume_dir(volume)
        volume_file = self.get_active_image_from_info(volume)
        volume_path = os.path.join(volume_dir, volume_file)
        volume_info = self._qemu_img_info(volume_path, volume.name)
        volume_format = volume_info.file_format
        if volume_format not in ['raw', 'qcow2']:
            message = (_('%(volume_type)s volume file %(volume_path)s '
                         'must be a valid raw or qcow2 image. '
                         'But is: %(volume_format)s')
                       % {'volume_type': self.driver_volume_type,
                          'volume_path': volume_path,
                          'volume_format': volume_format})
            raise exception.InvalidVolume(message)
        data = {
            'export': volume.provider_location,
            'format': volume_format,
            'name': volume_file
        }
        if self.shares.get(volume.provider_location):
            data['options'] = self.shares[volume.provider_location]
        connection_info = {
            'driver_volume_type': self.driver_volume_type,
            'mount_point_base': self.base,
            'data': data
        }
        LOG.debug('%(volume_type)s connection info for volume '
                  '%(volume)s: %(connection_info)s',
                  {'volume_type': self.driver_volume_type,
                   'volume': volume.id,
                   'connection_info': connection_info})
        return connection_info

    def terminate_connection(self, volume, connector, **kwargs):
        """Disallow connection from connector."""
        pass

    @coordination.synchronized('{self.driver_prefix}-{volume.id}')
    def create_volume(self, volume):
        """Apply locking to the create volume operation."""
        return super(LustreDriver, self).create_volume(volume)

    @coordination.synchronized('{self.driver_prefix}-{volume.id}')
    def delete_volume(self, volume):
        """Deletes a logical volume."""
        LOG.debug('Deleting volume %(volume)s with provider '
                  'location: %(location)s',
                  {'volume': volume.id,
                   'location': volume.provider_location})
        if not volume.provider_location:
            LOG.warning('Volume %(volume)s does not have provider '
                        'location specified, skipping',
                        {'volume': volume.id})
            return
        info_path = self._local_path_volume_info(volume)
        info = self._read_info_file(info_path, empty_if_missing=True)
        if info.get('active'):
            volume_dir = self._local_volume_dir(volume)
            volume_path = os.path.join(volume_dir, info['active'])
            self._delete(info_path)
        else:
            volume_path = self._local_path_volume(volume)
        self._delete(volume_path)

    @coordination.synchronized('{self.driver_prefix}-{volume.id}')
    def extend_volume(self, volume, new_size):
        """Extend an existing volume to the new size."""

        LOG.info('Extending volume %(volume)s to %(size)sG.',
                 {'volume': volume.id, 'size': new_size})
        path = self.local_path(volume)
        image_utils.resize_image(path, new_size,
                                 run_as_root=self._execute_as_root)
        info = self._qemu_img_info(path, volume.name)
        size = info.virtual_size / units.Gi
        if size != new_size:
            reason = (_('Failed to extend volume %(volume)s, expected '
                        'volume size %(new_size)sG but got %(size)sG')
                      % {'volume': volume.id, 'new_size': new_size,
                         'size': size})
            raise exception.ExtendVolumeError(reason=reason)

    @coordination.synchronized('{self.driver_prefix}-{share}')
    def _ensure_share_mounted(self, share):
        """Mount Lustre share.

        :param share: string
        """
        self._remotefsclient.mount(share)
        mount_path = self._get_mount_point_for_share(share)
        group_id = os.getegid()
        current_group_id = utils.get_file_gid(mount_path)
        current_mode = utils.get_file_mode(mount_path)
        if group_id != current_group_id:
            cmd = ['chgrp', group_id, mount_path]
            self._execute(*cmd, run_as_root=True)
        if not (current_mode & stat.S_IWGRP):
            cmd = ['chmod', 'g+w', mount_path]
            self._execute(*cmd, run_as_root=True)

    def _find_share(self, volume):
        """Choose Lustre share among available ones for given volume size.

        For instances with more than one share that meets the criteria,
        the share with the max "available" space will be selected.

        :param volume: the volume to be created.
        """
        if not self._mounted_shares:
            raise LustreNoSharesMounted()
        target_share = None
        target_available = 0
        for share in self._mounted_shares:
            available = self._get_available_capacity(share)[0]
            if available > target_available:
                target_share = share
                target_available = available
        if volume.size * units.Gi > target_available:
            raise LustreNoSuitableShareFound(volume_size=volume.size)
        LOG.debug('Selected %(share)s as target Lustre '
                  'share to create volume %(volume)s.',
                  {'share': target_share,
                   'volume': volume.name})
        return target_share

    # Workaround for ES-32
    def _create_volume_from_snapshot(self, volume, snapshot):
        """Creates a volume from a snapshot.

        Snapshot must not be the active snapshot. (offline)
        """
        LOG.debug('Creating volume %(vol)s from snapshot %(snap)s',
                  {'vol': volume.id, 'snap': snapshot.id})
        if snapshot.status not in ['available', 'backing-up']:
            msg = (_('Snapshot status must be "available" or '
                     '"backing-up" to clone. But is: %(status)s')
                   % {'status': snapshot.status})
            raise exception.InvalidSnapshot(msg)
        self._ensure_shares_mounted()
        volume.provider_location = self._find_share(volume)
        self._do_create_volume(volume)
        self._copy_volume_from_snapshot(snapshot,
                                        volume,
                                        volume.size,
                                        snapshot.volume.encryption_key_id,
                                        volume.encryption_key_id)
        return {'provider_location': volume.provider_location}

    # Workaround for ES-15
    def _create_snapshot(self, snapshot):
        """Create a snapshot.

        If volume is attached, call to Nova to create snapshot, providing a
        qcow2 file. Cinder creates and deletes qcow2 files, but Nova is
        responsible for transitioning the VM between them and handling live
        transfers of data between files as required.

        If volume is detached, create locally with qemu-img. Cinder handles
        manipulation of qcow2 files.

        A file named volume-<uuid>.info is stored with the volume
        data and is a JSON table which contains a mapping between
        Cinder snapshot UUIDs and filenames, as these associations
        will change as snapshots are deleted.


        Basic snapshot operation:

        1. Initial volume file:
            volume-1234

        2. Snapshot created:
            volume-1234  <- volume-1234.aaaa

            volume-1234.aaaa becomes the new "active" disk image.
            If the volume is not attached, this filename will be used to
            attach the volume to a VM at volume-attach time.
            If the volume is attached, the VM will switch to this file as
            part of the snapshot process.

            Note that volume-1234.aaaa represents changes after snapshot
            'aaaa' was created.  So the data for snapshot 'aaaa' is actually
            in the backing file(s) of volume-1234.aaaa.

            This file has a qcow2 header recording the fact that volume-1234 is
            its backing file.  Delta changes since the snapshot was created are
            stored in this file, and the backing file (volume-1234) does not
            change.

            info file: { 'active': 'volume-1234.aaaa',
                         'aaaa':   'volume-1234.aaaa' }

        3. Second snapshot created:
            volume-1234 <- volume-1234.aaaa <- volume-1234.bbbb

            volume-1234.bbbb now becomes the "active" disk image, recording
            changes made to the volume.

            info file: { 'active': 'volume-1234.bbbb',  (* changed!)
                         'aaaa':   'volume-1234.aaaa',
                         'bbbb':   'volume-1234.bbbb' } (* added!)

        4. Snapshot deletion when volume is attached ('in-use' state):

            * When first snapshot is deleted, Cinder calls Nova for online
              snapshot deletion. Nova deletes snapshot with id "aaaa" and
              makes snapshot with id "bbbb" point to the base image.
              Snapshot with id "bbbb" is the active image.

              volume-1234 <- volume-1234.bbbb

              info file: { 'active': 'volume-1234.bbbb',
                           'bbbb':   'volume-1234.bbbb'
                         }

             * When second snapshot is deleted, Cinder calls Nova for online
               snapshot deletion. Nova deletes snapshot with id "bbbb" by
               pulling volume-1234's data into volume-1234.bbbb. This
               (logically) removes snapshot with id "bbbb" and the active
               file remains the same.

               volume-1234.bbbb

               info file: { 'active': 'volume-1234.bbbb' }

           TODO (deepakcs): Change this once Nova supports blockCommit for
                            in-use volumes.

        5. Snapshot deletion when volume is detached ('available' state):

            * When first snapshot is deleted, Cinder does the snapshot
              deletion. volume-1234.aaaa is removed from the snapshot chain.
              The data from it is merged into its parent.

              volume-1234.bbbb is rebased, having volume-1234 as its new
              parent.

              volume-1234 <- volume-1234.bbbb

              info file: { 'active': 'volume-1234.bbbb',
                           'bbbb':   'volume-1234.bbbb'
                         }

            * When second snapshot is deleted, Cinder does the snapshot
              deletion. volume-1234.aaaa is removed from the snapshot chain.
              The base image, volume-1234 becomes the active image for this
              volume again.

              volume-1234

              info file: { 'active': 'volume-1234' }  (* changed!)
        """
        LOG.debug('Creating %(type)s snapshot %(snap)s of volume %(vol)s',
                  {'snap': snapshot.id, 'vol': snapshot.volume.id,
                   'type': ('online'
                            if self._is_volume_attached(snapshot.volume)
                            else 'offline')})
        status = snapshot.volume.status
        acceptable_states = ['available', 'in-use', 'backing-up']
        if (snapshot.display_name and
                snapshot.display_name.startswith('tmp-snap-')):
            # This is an internal volume snapshot. In order to support
            # image caching, we'll allow creating/deleting such snapshots
            # while having volumes in 'downloading' state.
            acceptable_states.append('downloading')
        self._validate_state(status, acceptable_states)
        info_path = self._local_path_volume_info(snapshot.volume)
        snap_info = self._read_info_file(info_path, empty_if_missing=True)
        backing_filename = self.get_active_image_from_info(
            snapshot.volume)
        new_snap_path = self._get_new_snap_path(snapshot)
        if self._is_volume_attached(snapshot.volume):
            self._create_snapshot_online(snapshot,
                                         backing_filename,
                                         new_snap_path)
        else:
            self._do_create_snapshot(snapshot,
                                     backing_filename,
                                     new_snap_path)
        snap_info['active'] = os.path.basename(new_snap_path)
        snap_info[snapshot.id] = os.path.basename(new_snap_path)
        self._write_info_file(info_path, snap_info)

    @coordination.synchronized('{self.driver_prefix}-{volume.id}')
    def update_migrated_volume(self, ctxt, volume, new_volume,
                               original_volume_status):
        """Return the keys and values updated for migrated volume.

        This method should rename the back-end volume name(id) on the
        destination host back to its original name(id) on the source host.

        :param ctxt: The context used to run the method update_migrated_volume
        :param volume: The original volume that was migrated to this backend
        :param new_volume: The migration volume object that was created on
                           this backend as part of the migration process
        :param original_volume_status: The status of the original volume
        :returns: model_update to update DB with any needed changes
        """
        name_id = None
        if (original_volume_status == 'available' and
                volume.provider_location != new_volume.provider_location):
            current_name = CONF.volume_name_template % new_volume.id
            original_volume_name = CONF.volume_name_template % volume.id
            current_path = self.local_path(new_volume)
            original_path = current_path.replace(current_name,
                                                 original_volume_name)
            try:
                os.rename(current_path, original_path)
            except OSError:
                LOG.exception('Unable to rename the logical volume '
                              'for volume: %s', volume.id)
                # If the rename fails, _name_id should be set to the new
                # volume id and provider_location should be set to the
                # one from the new volume as well.
                name_id = new_volume._name_id or new_volume.id
        else:
            # The back-end will not be renamed.
            name_id = new_volume._name_id or new_volume.id
        return {'_name_id': name_id,
                'provider_location': new_volume.provider_location}

    @coordination.synchronized('{self.driver_prefix}-{snapshot.volume.id}')
    def create_snapshot(self, snapshot):
        """Apply locking to the create snapshot operation."""
        return self._create_snapshot(snapshot)

    @coordination.synchronized('{self.driver_prefix}-{snapshot.volume.id}')
    def delete_snapshot(self, snapshot):
        """Apply locking to the delete snapshot operation."""
        return self._delete_snapshot(snapshot)
