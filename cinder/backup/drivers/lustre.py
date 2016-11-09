# Copyright (c) 2017 DataDirect Networks, Inc.
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

"""Implementation of a backup service that uses Lustre as the backend."""

import os
import stat

from os_brick.remotefs import remotefs as remotefs_brick
from oslo_concurrency import processutils as putils
from oslo_config import cfg

from cinder.backup.drivers import posix
from cinder import exception
from cinder import interface
from cinder import utils


lustrebackup_service_opts = [
    cfg.StrOpt('lustre_backup_mount_point',
               default='$state_path/backup_mount',
               help='Base dir containing mount point for lustre share.'),
    cfg.StrOpt('lustre_backup_share',
               help='Lustre share in <hostname|ip>@tcp:/<fsname> format. '
                    'Eg: 1.2.3.4@tcp:/backup_vol'),
]

CONF = cfg.CONF
CONF.register_opts(lustrebackup_service_opts)


@interface.backupdriver
class LustreBackupDriver(posix.PosixBackupDriver):
    """Provides backup, restore and delete using Lustre repository."""

    def __init__(self, context, db_driver=None):
        self._check_configuration()
        self.backup_mount_point_base = CONF.lustre_backup_mount_point
        self.backup_share = CONF.lustre_backup_share
        self._execute = putils.execute
        self._root_helper = utils.get_root_helper()
        backup_path = self._init_backup_repo_path()
        super(LustreBackupDriver, self).__init__(context,
                                                 backup_path=backup_path)

    @staticmethod
    def _check_configuration():
        """Raises error if any required configuration flag is missing."""
        required_flags = ['lustre_backup_share']
        for flag in required_flags:
            if not getattr(CONF, flag, None):
                raise exception.ConfigNotFound(path=flag)

    def _init_backup_repo_path(self):
        remotefsclient = remotefs_brick.RemoteFsClient(
            'lustre',
            self._root_helper,
            lustre_mount_point_base=self.backup_mount_point_base)
        remotefsclient.mount(self.backup_share)

        # Ensure we can write to this share
        mount_path = remotefsclient.get_mount_point(self.backup_share)

        group_id = os.getegid()
        current_group_id = utils.get_file_gid(mount_path)
        current_mode = utils.get_file_mode(mount_path)

        if group_id != current_group_id:
            cmd = ['chgrp', group_id, mount_path]
            self._execute(*cmd, root_helper=self._root_helper,
                          run_as_root=True)

        if not (current_mode & stat.S_IWGRP):
            cmd = ['chmod', 'g+w', mount_path]
            self._execute(*cmd, root_helper=self._root_helper,
                          run_as_root=True)

        return mount_path


def get_backup_driver(context):
    return LustreBackupDriver(context)
