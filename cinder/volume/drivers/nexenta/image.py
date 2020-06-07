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

import os

from oslo_utils import units

from cinder.image import image_utils
from cinder.volume.drivers.nexenta import utils

FILE_NAME = 'volume'
FORMAT_RAW = 'raw'
FORMAT_QCOW = 'qcow'
FORMAT_QCOW2 = 'qcow2'
FORMAT_PARALLELS = 'parallels'
FORMAT_VDI = 'vdi'
FORMAT_VHDX = 'vhdx'
FORMAT_VMDK = 'vmdk'
FORMAT_VPC = 'vpc'
FORMAT_QED = 'qed'


class VolumeImage(object):
    def __init__(self, driver, volume, specs):
        self.driver = driver
        self.nohide = driver.nas_nohide
        self.root = driver._execute_as_root
        self.block_size = driver.configuration.volume_dd_blocksize
        self.resizable_formats = [FORMAT_RAW, FORMAT_QCOW2]
        self.file_size = volume['size'] * units.Gi
        self.file_format = specs['format']
        self.file_sparse = specs['sparse']
        self.share = driver._get_volume_share(volume)
        if self.nohide:
            self.mntpoint = driver.nas_mntpoint
            self.file_name = os.path.join(volume['name'], FILE_NAME)
        else:
            self.mntpoint = driver._mount_share(self.share)
            self.file_name = FILE_NAME
        self.file_path = os.path.join(self.mntpoint, self.file_name)

    def __del__(self):
        if not self.nohide:
            self.driver._unmount_share(self.share, self.mntpoint)

    @property
    def info(self):
        return image_utils.qemu_img_info(
            self.file_path,
            run_as_root=self.root)

    @property
    def volume_size(self):
        return utils.roundgb(self.file_size)

    def execute(self, *cmd, **kwargs):
        if 'run_as_root' not in kwargs:
            kwargs['run_as_root'] = self.root
        self.driver._execute(*cmd, **kwargs)

    def create(self):
        cmd = ['qemu-img', 'create', '-f']
        cmd.append(self.file_format)
        if self.file_format == FORMAT_QCOW2:
            cmd.append('-o')
            cmd.append('preallocation=metadata')
        cmd.append(self.file_path)
        cmd.append(self.file_size)
        self.execute(*cmd)

    def resize(self, file_size):
        cmd = ['qemu-img', 'resize', '-f']
        cmd.append(self.file_format)
        if self.file_format == FORMAT_QCOW2:
            cmd.append('--preallocation=metadata')
        cmd.append(self.file_path)
        cmd.append(file_size)
        self.execute(*cmd)
        self.file_size = file_size

    def change(self, file_size=None, file_format=None):
        if not file_size:
            file_size = self.file_size
        if not file_format:
            file_format = self.file_format
        while (self.file_format != file_format
               or self.file_size != file_size):
            if self.file_size == file_size:
                self.convert(file_format)
            elif self.file_format in self.resizable_formats:
                self.resize(file_size)
            elif file_format in self.resizable_formats:
                self.convert(file_format)
            else:
                self.convert(FORMAT_RAW)

    def upload(self, ctxt, image_service, image_meta):
        image_utils.upload_volume(
            ctxt, image_service,
            image_meta, self.file_path,
            volume_format=self.file_format,
            run_as_root=self.root)

    def fetch(self, ctxt, image_service, image_id):
        image_utils.fetch_to_volume_format(
            ctxt, image_service,
            image_id, self.file_path,
            self.file_format,
            self.block_size,
            run_as_root=self.root)
        self.reload(file_size=True)

    def download(self, ctxt, image_service, image_id):
        file_size = self.file_size
        file_format = self.file_format
        if self.file_format not in self.resizable_formats:
            self.file_format = FORMAT_RAW
        self.fetch(ctxt, image_service, image_id)
        self.change(file_size=file_size, file_format=file_format)

    def convert(self, file_format):
        file_path = '%(path)s.%(format)s' % {
            'path': self.file_path,
            'format': file_format
        }
        image_utils.convert_image(
            self.file_path,
            file_path,
            file_format,
            src_format=self.file_format,
            run_as_root=self.root)
        self.execute('mv', file_path, self.file_path)
        self.file_format = file_format

    def reload(self, file_size=False, file_format=False):
        info = self.info
        if file_size:
            self.file_size = info.virtual_size
        if file_format:
            self.file_format = info.file_format
