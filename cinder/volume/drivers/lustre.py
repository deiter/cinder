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
                help='Create volumes as QCOW2 files rather than raw files.')
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
class LustreDriver(remotefs.RemoteFSSnapDriverDistributed):
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

    # ThirdPartySystems wiki page
    CI_WIKI_NAME = "Lustre_CI"

    def __init__(self, execute=processutils.execute, *args, **kwargs):
        self._remotefsclient = None
        super(LustreDriver, self).__init__(*args, **kwargs)
        self.configuration.append_config_values(lustre_opts)
        root_helper = utils.get_root_helper()
        self.configuration.nas_host = getattr(self.configuration,
                                              'lustre_share_host',
                                              CONF.lustre_share_host)
        self.configuration.nas_share_path = getattr(self.configuration,
                                                    'lustre_share_path',
                                                    CONF.lustre_share_path)
        self.base = getattr(self.configuration,
                            'lustre_mount_point_base',
                            CONF.lustre_mount_point_base)
        self.base = os.path.realpath(self.base)
        lustre_mount_options = getattr(self.configuration,
                                       'lustre_mount_options',
                                       CONF.lustre_mount_options)

        self._remotefsclient = remotefs_brick.RemoteFsClient(
            self.driver_volume_type, root_helper, execute=execute,
            lustre_mount_point_base=self.base,
            lustre_mount_options=lustre_mount_options)
        self._sparse_copy_volume_data = True
        self._supports_encryption = True

    def check_for_setup_error(self):
        package = 'mount.lustre'
        try:
            self._execute(package, check_exit_code=False)
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                msg = _('Package %s is not installed') % package
                raise LustreException(msg)
            raise
        self._refresh_mounts()

    def _unmount_shares(self):
        self._load_shares_config()
        for share in self.shares:
            try:
                self._do_umount(True, share)
            except Exception as exc:
                LOG.warning('Exception during unmounting %s', exc)

    @coordination.synchronized('{self.driver_prefix}-{share}')
    def _do_umount(self, ignore_not_mounted, share):
        mntpoints = self._remotefsclient._read_mounts()
        mntpoint = self._get_mount_point_for_share(share)
        if mntpoint not in mntpoints:
            LOG.debug('Lustre share %(share)s is not mounted at %(mntpoint)s',
                      {'share': share, 'mntpoint': mntpoint})
            return
        try:
            fs.umount(mntpoint)
        except processutils.ProcessExecutionError as exc:
            if 'target is busy' in exc.stderr:
                LOG.warning("Failed to refresh mounts, reason=%s",
                            exc.stderr)
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

        thin_enabled = self.configuration.nas_volume_prov_type == 'thin'
        if thin_enabled:
            provisioned_capacity = self._get_provisioned_capacity()
        else:
            provisioned_capacity = round(global_capacity - global_free, 2)

        data['provisioned_capacity_gb'] = provisioned_capacity
        data['max_over_subscription_ratio'] = (
            self.configuration.max_over_subscription_ratio)
        data['thin_provisioning_support'] = thin_enabled
        data['thick_provisioning_support'] = not thin_enabled
        data['multiattach'] = not self.configuration.lustre_qcow2_volumes

        self._stats = data

    def _copy_volume_from_snapshot(self, snapshot, volume, volume_size,
                                   src_encryption_key_id=None,
                                   new_encryption_key_id=None):
        """Copy data from snapshot to destination volume.

        This is done with a qemu-img convert to raw/qcow2 from the snapshot
        qcow2.
        """

        LOG.debug("Copying snapshot: %(snap)s -> volume: %(vol)s, "
                  "volume_size: %(size)s GB",
                  {'snap': snapshot.id,
                   'vol': volume.id,
                   'size': volume_size})

        info_path = self._local_path_volume_info(snapshot.volume)
        snap_info = self._read_info_file(info_path)
        vol_path = self._local_volume_dir(snapshot.volume)
        forward_file = snap_info[snapshot.id]
        forward_path = os.path.join(vol_path, forward_file)

        # Find the file which backs this file, which represents the point
        # when this snapshot was created.
        img_info = self._qemu_img_info(forward_path, snapshot.volume.name)
        path_to_snap_img = os.path.join(vol_path, img_info.backing_file)

        path_to_new_vol = self._local_path_volume(volume)

        LOG.debug("will copy from snapshot at %s", path_to_snap_img)

        if self.configuration.lustre_qcow2_volumes:
            out_format = 'qcow2'
        else:
            out_format = 'raw'

        if new_encryption_key_id is not None:
            if src_encryption_key_id is None:
                message = _("Can't create an encrypted volume %(format)s "
                            "from an unencrypted source."
                            ) % {'format': out_format}
                LOG.error(message)
                # TODO(enriquetaso): handle unencrypted snap->encrypted vol
                raise exception.NfsException(message)
            keymgr = key_manager.API(CONF)
            new_key = keymgr.get(volume.obj_context, new_encryption_key_id)
            new_passphrase = \
                binascii.hexlify(new_key.get_encoded()).decode('utf-8')

            # volume.obj_context is the owner of this request
            src_key = keymgr.get(volume.obj_context, src_encryption_key_id)
            src_passphrase = \
                binascii.hexlify(src_key.get_encoded()).decode('utf-8')

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
                                      out_format,
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

    @coordination.synchronized('{self.driver_prefix}-{volume[id]}')
    def initialize_connection(self, volume, connector):
        """Allow connection to connector and return connection info."""

        # Find active qcow2 file
        active_file = self.get_active_image_from_info(volume)
        path = '%s/%s/%s' % (self.base,
                             self._get_hash_str(volume.provider_location),
                             active_file)

        data = {'export': volume.provider_location,
                'name': active_file}
        if volume.provider_location in self.shares:
            data['options'] = self.shares[volume.provider_location]

        # Test file for raw vs. qcow2 format
        info = self._qemu_img_info(path, volume.name)
        data['format'] = info.file_format
        if data['format'] not in ['raw', 'qcow2']:
            msg = _('%s must be a valid raw or qcow2 image.') % path
            raise exception.InvalidVolume(msg)

        return {
            'driver_volume_type': self.driver_volume_type,
            'data': data,
            'mount_point_base': self._get_mount_point_base()
        }

    def terminate_connection(self, volume, connector, **kwargs):
        """Disallow connection from connector."""
        pass

    def extend_volume(self, volume, new_size):
        """Extend an existing volume to the new size."""

        LOG.info('Extending volume %(volume)s to %(size)sG.',
                 {'volume': volume.name, 'size': new_size})
        path = self.local_path(volume)
        image_utils.resize_image(path, new_size,
                                 run_as_root=self._execute_as_root)
        info = self._qemu_img_info(path, volume.name)
        size = info.virtual_size / units.Gi
        if size != new_size:
            raise exception.ExtendVolumeError(
                reason='Resizing image file failed.')

    @coordination.synchronized('{self.driver_prefix}-{share}')
    def _ensure_share_mounted(self, share):
        """Mount Lustre share.

        :param share: string
        """
        mount_path = self._get_mount_point_for_share(share)
        self._mount_lustre(share)

        # TODO(deiter): secure NAS/mount_attempts
        # Ensure we can write to this share
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

    def _mount_lustre(self, lustre_share):
        """Mount Lustre share to mount path."""
        mnt_flags = []
        if self.shares.get(lustre_share) is not None:
            mnt_flags = self.shares[lustre_share].split()
        try:
            self._remotefsclient.mount(lustre_share, mnt_flags)
        except processutils.ProcessExecutionError:
            LOG.error("Mount failure for %(share)s.",
                      {'share': lustre_share})
            raise
