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

from oslo_config import cfg

NEXENTASTOR_CONNECTION_OPTS = [
    cfg.BoolOpt('nexenta_use_https',
                deprecated_for_removal=True,
                deprecated_reason='NexentaStor RESTful API interface '
                                  'protocol should now be set using the '
                                  'common parameter nexenta_rest_protocol.',
                help='Use HTTP secure protocol for NexentaStor '
                     'management REST API connections.'),
    cfg.StrOpt('nexenta_rest_protocol',
               default='auto',
               choices=['http', 'https', 'auto'],
               help='NexentaStor RESTful API interface protocol.'),
    cfg.IntOpt('nexenta_rest_port',
               default=0,
               help='NexentaStor RESTful API interface port. If it is '
                    'equal zero, 8443 for HTTPS and 8080 for HTTP will '
                    'be used for NexentaStor5 and 8457 for NexentaStor4.'),
    cfg.StrOpt('nexenta_user',
               default='admin',
               help='User name to connect to NexentaStor RESTful API '
                    'interface.'),
    cfg.StrOpt('nexenta_password',
               default='nexenta',
               help='User password to connect to NexentaStor RESTful API '
                    'interface.',
               secret=True),
    cfg.StrOpt('nexenta_rest_address',
               default='',
               help='IP address of NexentaStor RESTful API interface.'),
    cfg.FloatOpt('nexenta_rest_connect_timeout',
                 default=30,
                 help='Specifies the time limit (in seconds), within '
                      'which the connection to NexentaStor RESTful '
                      'API interface must be established.'),
    cfg.FloatOpt('nexenta_rest_read_timeout',
                 default=300,
                 help='Specifies the time limit (in seconds), '
                      'within which NexentaStor RESTful API '
                      'interface must send a response.'),
    cfg.FloatOpt('nexenta_rest_backoff_factor',
                 default=1,
                 help='Specifies the backoff factor to apply between '
                      'connection attempts to NexentaStor RESTful '
                      'API interface.'),
    cfg.IntOpt('nexenta_rest_retry_count',
               default=5,
               help='Specifies the number of times to repeat NexentaStor '
                    'RESTful API calls in case of connection errors '
                    'or NexentaStor appliance retryable errors.')
]

NEXENTASTOR_ISCSI_OPTS = [
    cfg.StrOpt('nexenta_host',
               default='',
               help='IP address of NexentaStor iSCSI target.'),
    cfg.StrOpt('nexenta_volume',
               default='cinder',
               help='NexentaStor pool name that holds all volumes.'),
    cfg.IntOpt('nexenta_iscsi_target_portal_port',
               default=3260,
               help='NexentaStor default iSCSI target portal port.'),
    cfg.StrOpt('nexenta_target_prefix',
               default='iqn.2005-07.com.nexenta:01:cinder',
               help='Prefix for NexentaStor iSCSI targets.'),
    cfg.StrOpt('nexenta_target_group_prefix',
               default='cinder',
               help='Prefix for iSCSI target groups on NexentaStor.'),
    cfg.StrOpt('nexenta_host_group_prefix',
               default='cinder',
               help='Prefix for iSCSI host groups on NexentaStor.'),
    cfg.BoolOpt('nexenta_lu_writebackcache_disabled',
                default=False,
                help='iSCSI LUNs write-back cache disable behavior: '
                     'postponed write to backing store is disabled or no.'),
    cfg.IntOpt('nexenta_luns_per_target',
               default=100,
               help='Limit of LUNs per iSCSI target.'),
    cfg.StrOpt('nexenta_iscsi_target_host_group',
               deprecated_for_removal=True,
               deprecated_reason='NexentaStor cinder driver has been '
                                 'refactored and host groups are created '
                                 'dynamically. So the configuration '
                                 'parameter nexenta_iscsi_target_host_group '
                                 'is no longer used.',
               default='all',
               help='Group of hosts which are allowed to access volumes.'),
    cfg.BoolOpt('nexenta_sparse',
                deprecated_for_removal=True,
                deprecated_reason='Common provisioning parameter should '
                                  'be used: nexenta_sparsed_volumes.',
                default=False,
                help='Enables or disables the creation of sparse datasets.')
]

NEXENTAEDGE_ISCSI_OPTS = [
    cfg.StrOpt('nexenta_nbd_symlinks_dir',
               default='/dev/disk/by-path',
               help='NexentaEdge logical path of directory to store symbolic '
                    'links to NBDs.'),
    cfg.StrOpt('nexenta_rest_user',
               default='admin',
               help='User name to connect to NexentaEdge.'),
    cfg.StrOpt('nexenta_rest_password',
               default='nexenta',
               help='Password to connect to NexentaEdge.',
               secret=True),
    cfg.StrOpt('nexenta_lun_container',
               default='',
               help='NexentaEdge logical path of bucket for LUNs.'),
    cfg.StrOpt('nexenta_iscsi_service',
               default='',
               help='NexentaEdge iSCSI service name.'),
    cfg.StrOpt('nexenta_client_address',
               default='',
               help='NexentaEdge iSCSI Gateway client '
               'address for non-VIP service'),
    cfg.IntOpt('nexenta_iops_limit',
               default=0,
               help='NexentaEdge iSCSI LUN object IOPS limit.'),
    cfg.IntOpt('nexenta_chunksize',
               default=32768,
               help='NexentaEdge iSCSI LUN object chunk size.'),
    cfg.IntOpt('nexenta_replication_count',
               default=3,
               help='NexentaEdge iSCSI LUN object replication count.'),
    cfg.BoolOpt('nexenta_encryption',
                default=False,
                help='Defines whether NexentaEdge iSCSI LUN object '
                     'has encryption enabled.')
]

NEXENTASTOR4_ISCSI_OPTS = [
    cfg.StrOpt('nexenta_folder',
               default='',
               help='NexentaStor folder name that holds all volumes.'),
    cfg.ListOpt('nexenta_iscsi_target_portal_groups',
                default=[],
                help='List of comma-separated NexentaStor4 iSCSI target '
                     'portal groups.')
]

NEXENTASTOR5_ISCSI_OPTS = [
    cfg.StrOpt('nexenta_volume_group',
               default='iscsi',
               help='NexentaStor volume group name that holds all volumes.'),
    cfg.ListOpt('nexenta_iscsi_target_portals',
                default='',
                help='Comma separated list of portals for NexentaStor, in '
                     'format of IP:port,IP:port. Port number is optional, '
                     'default value is 3260.'),
    cfg.IntOpt('nexenta_ns5_blocksize',
               deprecated_for_removal=True,
               deprecated_reason='Common block size parameter should be '
                                 'used: nexenta_blocksize.',
               default=32,
               help='Block size for datasets.')
]

NEXENTA_NFS_OPTS = [
    cfg.StrOpt('nexenta_volume_format',
               default='raw',
               choices=['raw', 'qcow', 'qcow2', 'parallels',
                        'vdi', 'vhdx', 'vmdk', 'vpc', 'qed'],
               help='Volume image file format.'),
    cfg.BoolOpt('nexenta_nbmand',
                default=False,
                help='Allow or disallow non-blocking mandatory locking '
                     'semantics for a volume.'),
    cfg.BoolOpt('nexenta_smart_compression',
                default=False,
                help='Allow or disallow dynamically tracks per-volume '
                     'compression ratios to determine if a volume data '
                     'is compressible or not.'),
    cfg.BoolOpt('nexenta_qcow2_volumes',
                deprecated_for_removal=True,
                deprecated_reason='Volume format parameter should '
                                  'be used: nexenta_volume_format.',
                default=False,
                help='Create volumes as QCOW2 files rather than raw files.'),
    cfg.StrOpt('nexenta_shares_config',
               deprecated_for_removal=True,
               deprecated_reason='NexentaStor cinder driver has been '
                                 'refactored and the configuration '
                                 'parameter nexenta_shares_config '
                                 'is no longer used.',
               default='/etc/cinder/nfs_shares',
               help='File with the list of available nfs shares.'),
    cfg.StrOpt('nexenta_mount_point_base',
               default='$state_path/mnt',
               help='Base directory that contains NFS share mount points.'),
    cfg.BoolOpt('nexenta_nms_cache_volroot',
                deprecated_for_removal=True,
                deprecated_reason='NexentaStor cinder driver has been '
                                  'refactored and the configuration '
                                  'parameter nexenta_nms_cache_volroot '
                                  'is no longer used.',
                default=True,
                help='If set True cache NexentaStor appliance volroot '
                     'option value.')
]

NEXENTASTOR_DATASET_OPTS = [
    cfg.StrOpt('nexenta_dataset_compression',
               choices=['off', 'on', 'gzip', 'gzip-1', 'gzip-2', 'gzip-3',
                        'gzip-4', 'gzip-5', 'gzip-6', 'gzip-7', 'gzip-8',
                        'gzip-9', 'lzjb', 'zle', 'lz4'],
               help='Compression algorithm used to compress volume data.'),
    cfg.StrOpt('nexenta_dataset_dedup',
               choices=['off', 'on', 'sha256', 'verify', 'sha256,verify'],
               help='Deduplication algorithm used to verify volume data '
                    'integrity.'),
    cfg.BoolOpt('nexenta_sparsed_volumes',
                default=True,
                help='Volumes space allocation behavior. Whether volume '
                     'is created as sparse and grown as needed or fully '
                     'allocated up front. The default and recommended '
                     'value is true, which ensures volumes are initially '
                     'created as sparse devices. Setting value to false '
                     'will result in volumes being fully allocated at the '
                     'time of creation.'),
    cfg.BoolOpt('nexenta_image_cache',
                default=True,
                help='Enables an internal cache of images to efficiently '
                     'create a new volume by cloning an existing cached '
                     'image.'),
    cfg.IntOpt('nexenta_blocksize',
               default=32768,
               help='Specifies a suggested block size for a volume. '
                    'The size specified must be a power of two greater '
                    'than or equal to 512 and less than or equal to 131072 '
                    'bytes. For an NFS backend, the block size may be up '
                    'to 1048576 bytes. For an iSCSI backend, the block size '
                    'cannot be changed after the volume is created.'),
    cfg.IntOpt('nexenta_migration_throttle',
               min=1,
               max=2047,
               help='Throttle migration throughput in MegaBytes per second.'),
    cfg.StrOpt('nexenta_migration_service_prefix',
               default='cinder-migration',
               help='Prefix for migration service name.'),
    cfg.StrOpt('nexenta_migration_snapshot_prefix',
               default='migration-snapshot',
               help='Prefix for migration snapshot name.'),
    cfg.StrOpt('nexenta_origin_snapshot_template',
               default='origin-snapshot-%s',
               help='Template string to generate origin name of clone.'),
    cfg.StrOpt('nexenta_group_snapshot_template',
               default='group-snapshot-%s',
               help='Template string to generate group snapshot name.'),
    cfg.StrOpt('nexenta_cache_image_template',
               default='cache-image-%s',
               help='Template string to generate cache image name.'),
    cfg.StrOpt('nexenta_cache_snapshot_template',
               default='cache-snapshot-%s',
               help='Template string to generate cache snapshot name.'),
    cfg.StrOpt('nexenta_dataset_description',
               default='',
               help='Human-readable description for the backend.')
]

NEXENTASTOR4_RRMGR_OPTS = [
    cfg.IntOpt('nexenta_rrmgr_compression',
               deprecated_for_removal=True,
               deprecated_reason='NexentaStor cinder driver has been '
                                 'refactored and the configuration '
                                 'parameter nexenta_rrmgr_compression '
                                 'is no longer used.',
               default=0,
               help='Enable stream compression, level 1..9. 1 - gives best '
                    'speed; 9 - gives best compression.'),
    cfg.IntOpt('nexenta_rrmgr_tcp_buf_size',
               deprecated_for_removal=True,
               deprecated_reason='NexentaStor cinder driver has been '
                                 'refactored and the configuration '
                                 'parameter nexenta_rrmgr_tcp_buf_size '
                                 'is no longer used.',
               default=4096,
               help='TCP Buffer size in KiloBytes.'),
    cfg.IntOpt('nexenta_rrmgr_connections',
               deprecated_for_removal=True,
               deprecated_reason='NexentaStor cinder driver has been '
                                 'refactored and the configuration '
                                 'parameter nexenta_rrmgr_connections '
                                 'is no longer used.',
               default=2,
               help='Number of TCP connections.')
]

NEXENTAEDGE_ISCSI_OPTS += (
    NEXENTASTOR_CONNECTION_OPTS +
    NEXENTASTOR_DATASET_OPTS +
    NEXENTASTOR_ISCSI_OPTS
)

NEXENTASTOR4_ISCSI_OPTS += (
    NEXENTASTOR_CONNECTION_OPTS +
    NEXENTASTOR_DATASET_OPTS +
    NEXENTASTOR_ISCSI_OPTS +
    NEXENTASTOR4_RRMGR_OPTS
)

NEXENTASTOR5_ISCSI_OPTS += (
    NEXENTASTOR_CONNECTION_OPTS +
    NEXENTASTOR_DATASET_OPTS +
    NEXENTASTOR_ISCSI_OPTS
)

NEXENTASTOR4_NFS_OPTS = (
    NEXENTASTOR_CONNECTION_OPTS +
    NEXENTASTOR_DATASET_OPTS +
    NEXENTA_NFS_OPTS +
    NEXENTASTOR4_RRMGR_OPTS
)

NEXENTASTOR5_NFS_OPTS = (
    NEXENTASTOR_CONNECTION_OPTS +
    NEXENTASTOR_DATASET_OPTS +
    NEXENTA_NFS_OPTS
)

CONF = cfg.CONF
CONF.register_opts(NEXENTAEDGE_ISCSI_OPTS)
CONF.register_opts(NEXENTASTOR4_ISCSI_OPTS)
CONF.register_opts(NEXENTASTOR5_ISCSI_OPTS)
CONF.register_opts(NEXENTASTOR4_NFS_OPTS)
CONF.register_opts(NEXENTASTOR5_NFS_OPTS)
