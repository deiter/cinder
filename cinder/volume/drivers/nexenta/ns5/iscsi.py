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

import ipaddress
import random
import uuid
import six

from oslo_log import log as logging
from oslo_utils import units

from cinder import coordination
from cinder import interface
from cinder.i18n import _
from cinder.volume import driver
from cinder.volume.drivers.nexenta import options
from cinder.volume.drivers.nexenta.ns5.jsonrpc import NefProxy
from cinder.volume.drivers.nexenta.ns5.jsonrpc import NefException

VERSION = '1.4.0'
LOG = logging.getLogger(__name__)


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
        1.3.2 - Revert to snapshot support.
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
    """

    VERSION = VERSION

    # ThirdPartySystems wiki page
    CI_WIKI_NAME = "Nexenta_CI"

    def __init__(self, *args, **kwargs):
        super(NexentaISCSIDriver, self).__init__(*args, **kwargs)
        self.nef = None
        if self.configuration:
            self.configuration.append_config_values(
                options.NEXENTA_CONNECTION_OPTS)
            self.configuration.append_config_values(
                options.NEXENTA_ISCSI_OPTS)
            self.configuration.append_config_values(
                options.NEXENTA_DATASET_OPTS)
        self.target_prefix = self.configuration.nexenta_target_prefix
        self.target_group_prefix = (
            self.configuration.nexenta_target_group_prefix)
        self.host_group_prefix = self.configuration.nexenta_host_group_prefix
        self.luns_per_target = self.configuration.nexenta_luns_per_target
        self.lu_writebackcache_disabled = (
            self.configuration.nexenta_lu_writebackcache_disabled)
        self.iscsi_host = self.configuration.nexenta_host
        self.pool = self.configuration.nexenta_volume
        self.volume_group = self.configuration.nexenta_volume_group
        self.portal_port = self.configuration.nexenta_iscsi_target_portal_port
        self.portals = self.configuration.nexenta_iscsi_target_portals
        self.dataset_sparsed = self.configuration.nexenta_sparse
        self.dataset_deduplication = self.configuration.nexenta_dataset_dedup
        self.dataset_compression = (
            self.configuration.nexenta_dataset_compression)
        self.dataset_description = (
            self.configuration.nexenta_dataset_description)
        self.iscsi_target_portal_port = (
            self.configuration.nexenta_iscsi_target_portal_port)
        self.root_path = '%s/%s' % (self.pool, self.volume_group)
        self.lock = '%s:%s' % (self.backend_name, self.root_path)
        self.dataset_blocksize = self.configuration.nexenta_ns5_blocksize
        if not self.configuration.nexenta_ns5_blocksize > 128:
            self.dataset_blocksize *= units.Ki

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
        try:
            self.nef.volumegroups.get(self.root_path)
        except NefException as error:
            if error.code != 'ENOENT':
                raise error
            payload = {'path': self.root_path,
                       'volumeBlockSize': self.dataset_blocksize}
            self.nef.volumegroups.create(payload)

    def check_for_setup_error(self):
        """Check ZFS pool, volume group and iSCSI target service."""
        self.nef.pools.get(self.pool)
        self.nef.volumegroups.get(self.root_path)
        service = self.nef.services.get('iscsit')
        if service['state'] != 'online':
            message = (_('iSCSI target service is not online: %(state)s')
                       % {'state': service['state']})
            raise NefException({'code': 'ESRCH', 'message': message})

    def create_volume(self, volume):
        """Create a zfs volume on appliance.

        :param volume: volume reference
        :returns: model update dict for volume reference
        """
        payload = {
            'path': self._get_volume_path(volume),
            'volumeSize': volume['size'] * units.Gi,
            'volumeBlockSize': self.dataset_blocksize,
            'sparseVolume': self.dataset_sparsed
        }
        self.nef.volumes.create(payload)

    @coordination.synchronized('{self.lock}')
    def delete_volume(self, volume):
        """Deletes a logical volume.

        :param volume: volume reference
        """
        volume_path = self._get_volume_path(volume)
        delete_payload = {'snapshots': True}
        try:
            self.nef.volumes.delete(volume_path, delete_payload)
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
                self.nef.volumes.promote(clone_path)
            self.nef.volumes.delete(volume_path, delete_payload)

    def extend_volume(self, volume, new_size):
        """Extend an existing volume.

        :param volume: volume reference
        :param new_size: volume new size in GB
        """
        volume_path = self._get_volume_path(volume)
        payload = {'volumeSize': new_size * units.Gi}
        self.nef.volumes.set(volume_path, payload)

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
        self.nef.volumes.rollback(volume_path, payload)

    @coordination.synchronized('{self.lock}')
    def create_volume_from_snapshot(self, volume, snapshot):
        """Create new volume from other's snapshot on appliance.

        :param volume: reference of volume to be created
        :param snapshot: reference of source snapshot
        """
        snapshot_path = self._get_snapshot_path(snapshot)
        clone_path = self._get_volume_path(volume)
        payload = {'targetPath': clone_path}
        self.nef.snapshots.clone(snapshot_path, payload)
        if volume['size'] > snapshot['volume_size']:
            self.extend_volume(volume, volume['size'])

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
            self.create_volume_from_snapshot(volume, snapshot)
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

    def create_export(self, context, volume, connector):
        """Export a volume."""
        pass

    def ensure_export(self, context, volume):
        """Synchronously recreate an export for a volume."""
        pass

    def remove_export(self, context, volume):
        """Remove an export for a volume."""
        pass

    def terminate_connection(self, volume, connector, **kwargs):
        """Terminate a connection to a volume.

        :param volume: a volume object
        :param connector: a connector object
        :returns: dictionary of connection information
        """
        info = {'driver_volume_type': 'iscsi', 'data': {}}
        host_iqn = None
        host_groups = []
        volume_path = self._get_volume_path(volume)
        if isinstance(connector, dict) and 'initiator' in connector:
            connectors = []
            for attachment in volume.volume_attachment:
                connectors.append(attachment.get('connector'))
            if connectors.count(connector) > 1:
                LOG.debug('Detected multiple connections on host '
                          '%(host_name)s [%(host_ip)s] for volume '
                          '%(volume)s, skip terminate volume connection',
                          {'host_name': connector.get('host', 'unknown'),
                           'host_ip': connector.get('ip', 'unknown'),
                           'volume': volume['name']})
                return True
            host_iqn = connector.get('initiator')
            host_groups.append(options.DEFAULT_HOST_GROUP)
            host_group = self._get_host_group(host_iqn)
            if host_group is not None:
                host_groups.append(host_group)
            LOG.debug('Terminate connection for volume %(volume)s '
                      'and initiator %(initiator)s',
                      {'volume': volume['name'],
                       'initiator': host_iqn})
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
            if host_iqn is None or mapping_hg in host_groups:
                LOG.debug('Delete LUN mapping %(id)s for volume %(volume)s, '
                          'target group %(tg)s and host group %(hg)s',
                          {'id': mapping_id, 'volume': volume['name'],
                           'tg': mapping_tg, 'hg': mapping_hg})
                self._delete_lun_mapping(mapping_id)
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
        LOG.debug('Updating volume stats')
        payload = {'fields': 'bytesAvailable,bytesUsed'}
        stats = self.nef.volumegroups.get(self.root_path, payload)
        free = stats['bytesAvailable'] // units.Gi
        allocated = stats['bytesUsed'] // units.Gi

        location_info = '%(driver)s:%(host)s:%(pool)s/%(group)s' % {
            'driver': self.__class__.__name__,
            'host': self.iscsi_host,
            'pool': self.pool,
            'group': self.volume_group,
        }
        self._stats = {
            'vendor_name': 'Nexenta',
            'dedup': self.dataset_deduplication,
            'compression': self.dataset_compression,
            'description': self.dataset_description,
            'driver_version': self.VERSION,
            'storage_protocol': 'iSCSI',
            'sparsed_volumes': self.dataset_sparsed,
            'total_capacity_gb': free + allocated,
            'free_capacity_gb': free,
            'reserved_percentage': self.configuration.reserved_percentage,
            'QoS_support': False,
            'multiattach': True,
            'consistencygroup_support': True,
            'consistent_group_snapshot_enabled': True,
            'volume_backend_name': self.backend_name,
            'location_info': location_info,
            'iscsi_target_portal_port': self.iscsi_target_portal_port,
            'nef_url': self.nef.host,
            'nef_port': self.nef.port
        }

    def _get_volume_path(self, volume):
        """Return ZFS datset path for the volume."""
        return '%s/%s' % (self.root_path, volume['name'])

    def _get_snapshot_path(self, snapshot):
        """Return ZFS snapshot path for the snapshot."""
        return '%s/%s@%s' % (self.root_path, snapshot['volume_name'],
                             snapshot['name'])

    def _get_cgsnapshot_path(self, cgsnapshot):
        """Return ZFS snapshot path for the consistency group snapshot."""
        name = self._get_cgsnapshot_name(cgsnapshot)
        return '%s@%s' % (self.root_path, name)

    @staticmethod
    def _get_clone_snapshot_name(volume):
        """Return snapshot name that will be used to clone the volume."""
        return 'cinder-clone-snapshot-%s' % volume['id']

    @staticmethod
    def _get_cgsnapshot_name(cgsnapshot):
        """Return cgsnapshot name for the consistency group snapshot."""
        return 'cgsnapshot-%s' % cgsnapshot['id']

    def _get_target_group_name(self, target_name):
        """Return Nexenta iSCSI target group name for volume."""
        return target_name.replace(
            self.configuration.nexenta_target_prefix,
            self.configuration.nexenta_target_group_prefix
        )

    def _get_target_name(self, target_group_name):
        """Return Nexenta iSCSI target name for volume."""
        return target_group_name.replace(
            self.configuration.nexenta_target_group_prefix,
            self.configuration.nexenta_target_prefix
        )

    def _get_host_addresses(self):
        """Return Nexenta IP addresses list."""
        host_addresses = []
        items = self.nef.netaddrs.list()
        for item in items:
            ip_cidr = six.text_type(item['address'])
            ip_addr, ip_mask = ip_cidr.split('/')
            ip_obj = ipaddress.ip_address(ip_addr)
            if not ip_obj.is_loopback:
                host_addresses.append(ip_obj.exploded)
        LOG.debug('Configured IP addresses: %(addresses)s',
                  {'addresses': host_addresses})
        return host_addresses

    def _get_host_portals(self):
        """Return configured iSCSI portals list."""
        host_portals = []
        host_addresses = self._get_host_addresses()
        portal_host = self.iscsi_host
        if portal_host:
            if portal_host in host_addresses:
                if self.portal_port:
                    portal_port = int(self.portal_port)
                else:
                    portal_port = options.DEFAULT_ISCSI_PORT
                host_portal = '%s:%s' % (portal_host, portal_port)
                host_portals.append(host_portal)
            else:
                LOG.debug('Skip not a local portal IP address %(portal)s',
                          {'portal': portal_host})
        else:
            LOG.debug('Configuration parameter nexenta_host is not defined')
        for portal in self.portals.split(','):
            if not portal:
                continue
            host_port = portal.split(':')
            portal_host = host_port[0]
            if portal_host in host_addresses:
                if len(host_port) == 2:
                    portal_port = int(host_port[1])
                else:
                    portal_port = options.DEFAULT_ISCSI_PORT
                host_portal = '%s:%s' % (portal_host, portal_port)
                if host_portal not in host_portals:
                    host_portals.append(host_portal)
            else:
                LOG.debug('Skip not a local portal IP address %(portal)s',
                          {'portal': portal_host})
        LOG.debug('Configured iSCSI portals: %(portals)s',
                  {'portals': host_portals})
        return host_portals

    def _target_group_props(self, group_name, host_portals):
        """Check and update an existing targets/portals for given target group.

        :param group_name: target group name
        :param host_portals: configured host portals list
        :returns: dictionary of portals per target
        """
        if not group_name.startswith(self.target_group_prefix):
            LOG.debug('Skip not a cinder target group %(group)s',
                      {'group': group_name})
            return {}
        group_props = {}
        payload = {'name': group_name}
        data = self.nef.targetgroups.list(payload)
        if not data:
            LOG.debug('Skip target group %(group)s: group not found',
                      {'group': group_name})
            return {}
        target_names = data[0]['members']
        if not target_names:
            target_name = self._get_target_name(group_name)
            self._create_target(target_name, host_portals)
            self._update_target_group(group_name, [target_name])
            group_props[target_name] = host_portals
            return group_props
        for target_name in target_names:
            group_props[target_name] = []
            payload = {'name': target_name}
            data = self.nef.targets.list(payload)
            if not data:
                LOG.debug('Skip target group %(group)s: '
                          'group member %(target)s not found',
                          {'group': group_name, 'target': target_name})
                return {}
            target_portals = data[0]['portals']
            if not target_portals:
                LOG.debug('Skip target group %(group)s: '
                          'group member %(target)s has no portals',
                          {'group': group_name, 'target': target_name})
                return {}
            for item in target_portals:
                target_portal = '%s:%s' % (item['address'], item['port'])
                if target_portal not in host_portals:
                    LOG.debug('Skip target group %(group)s: '
                              'group member %(target)s bind to a '
                              'non local portal address %(portal)s',
                              {'group': group_name,
                               'target': target_name,
                               'portal': target_portal})
                    return {}
                group_props[target_name].append(target_portal)
        return group_props

    def initialize_connection(self, volume, connector):
        """Do all steps to get zfs volume exported at separate target.

        :param volume: volume reference
        :param connector: connector reference
        :returns: dictionary of connection information
        """
        volume_path = self._get_volume_path(volume)
        host_iqn = connector.get('initiator')
        LOG.debug('Initialize connection for volume: %(volume)s '
                  'and initiator: %(initiator)s',
                  {'volume': volume_path, 'initiator': host_iqn})

        host_groups = [options.DEFAULT_HOST_GROUP]
        host_group = self._get_host_group(host_iqn)
        if host_group:
            host_groups.append(host_group)

        host_portals = self._get_host_portals()
        props_portals = []
        props_iqns = []
        props_luns = []
        payload = {'volume': volume_path}
        mappings = self.nef.mappings.list(payload)
        for mapping in mappings:
            mapping_id = mapping['id']
            mapping_lu = mapping['lun']
            mapping_hg = mapping['hostGroup']
            mapping_tg = mapping['targetGroup']
            if mapping_tg == options.DEFAULT_TARGET_GROUP:
                LOG.debug('Delete LUN mapping %(id)s for target group %(tg)s',
                          {'id': mapping_id, 'tg': mapping_tg})
                self._delete_lun_mapping(mapping_id)
                continue
            if mapping_hg not in host_groups:
                LOG.debug('Skip LUN mapping %(id)s for host group %(hg)s',
                          {'id': mapping_id, 'hg': mapping_hg})
                continue
            group_props = self._target_group_props(mapping_tg, host_portals)
            if not group_props:
                LOG.debug('Skip LUN mapping %(id)s for target group %(tg)s',
                          {'id': mapping_id, 'tg': mapping_tg})
                continue
            for target_iqn in group_props:
                target_portals = group_props[target_iqn]
                props_portals += target_portals
                props_iqns += [target_iqn] * len(target_portals)
                props_luns += [mapping_lu] * len(target_portals)

        props = {}
        props['target_discovered'] = False
        props['encrypted'] = False
        props['qos_specs'] = None
        props['volume_id'] = volume['id']
        props['access_mode'] = 'rw'
        multipath = connector.get('multipath', False)

        if props_luns:
            if multipath:
                props['target_portals'] = props_portals
                props['target_iqns'] = props_iqns
                props['target_luns'] = props_luns
            else:
                index = random.randrange(0, len(props_luns))
                props['target_portal'] = props_portals[index]
                props['target_iqn'] = props_iqns[index]
                props['target_lun'] = props_luns[index]
            LOG.debug('Use existing LUN mapping(s) %(props)s',
                      {'props': props})
            return {'driver_volume_type': 'iscsi', 'data': props}

        if host_group is None:
            host_group = '%s-%s' % (self.host_group_prefix, uuid.uuid4().hex)
            self._create_host_group(host_group, [host_iqn])

        mappings_spread = {}
        targets_spread = {}
        data = self.nef.targetgroups.list()
        for item in data:
            target_group = item['name']
            group_props = self._target_group_props(target_group, host_portals)
            members = len(group_props)
            if members == 0:
                LOG.debug('Skip unsuitable target group %(tg)s',
                          {'tg': target_group})
                continue
            payload = {'targetGroup': target_group}
            data = self.nef.mappings.list(payload)
            mappings = len(data)
            if not mappings < self.luns_per_target:
                LOG.debug('Skip target group %(tg)s: '
                          'group members limit reached: %(limit)s',
                          {'tg': target_group, 'limit': mappings})
                continue
            targets_spread[target_group] = group_props
            mappings_spread[target_group] = mappings
            LOG.debug('Found target group %(tg)s with %(members)s '
                      'members and %(mappings)s LUNs',
                      {'tg': target_group, 'members': members,
                       'mappings': mappings})

        if not mappings_spread:
            target = '%s-%s' % (self.target_prefix, uuid.uuid4().hex)
            target_group = self._get_target_group_name(target)
            self._create_target(target, host_portals)
            self._create_target_group(target_group, [target])
            props_portals += host_portals
            props_iqns += [target] * len(host_portals)
        else:
            target_group = min(mappings_spread, key=mappings_spread.get)
            targets = targets_spread[target_group]
            members = targets.keys()
            mappings = mappings_spread[target_group]
            LOG.debug('Using existing target group %(tg)s '
                      'with members %(members)s and %(mappings)s LUNs',
                      {'tg': target_group, 'members': members,
                       'mappings': mappings})
            for target in targets:
                portals = targets[target]
                props_portals += portals
                props_iqns += [target] * len(portals)

        payload = {'volume': volume_path,
                   'targetGroup': target_group,
                   'hostGroup': host_group}
        self.nef.mappings.create(payload)
        mapping = {}
        for attempt in range(0, self.nef.retries):
            mapping = self.nef.mappings.list(payload)
            if mapping:
                break
            self.nef.delay(attempt)
        if not mapping:
            message = (_('Failed to get LUN number for %(volume)s')
                       % {'volume': volume_path})
            raise NefException({'code': 'ENOTBLK', 'message': message})
        lun = mapping[0]['lun']
        props_luns = [lun] * len(props_iqns)

        if multipath:
            props['target_portals'] = props_portals
            props['target_iqns'] = props_iqns
            props['target_luns'] = props_luns
        else:
            index = random.randrange(0, len(props_luns))
            props['target_portal'] = props_portals[index]
            props['target_iqn'] = props_iqns[index]
            props['target_lun'] = props_luns[index]

        if not self.lu_writebackcache_disabled:
            LOG.debug('Get LUN guid for volume %(volume)s',
                      {'volume': volume_path})
            payload = {'fields': 'guid', 'volume': volume_path}
            data = self.nef.logicalunits.list(payload)
            guid = data[0]['guid']
            payload = {'writebackCacheDisabled': False}
            self.nef.logicalunits.set(guid, payload)

        LOG.debug('Created new LUN mapping(s): %(props)s',
                  {'props': props})
        return {'driver_volume_type': 'iscsi', 'data': props}

    def _create_target_group(self, name, members):
        """Create a new target group with members.

        :param name: group name
        :param members: group members list
        """
        payload = {'name': name, 'members': members}
        self.nef.targetgroups.create(payload)

    def _update_target_group(self, name, members):
        """Update a existing target group with new members.

        :param name: group name
        :param members: group members list
        """
        payload = {'members': members}
        self.nef.targetgroups.set(name, payload)

    def _delete_lun_mapping(self, name):
        """Delete an existing LUN mapping.

        :param name: LUN mapping ID
        """
        self.nef.mappings.delete(name)

    def _create_target(self, name, portals):
        """Create a new target with portals.

        :param name: target name
        :param portals: target portals list
        """
        payload = {'name': name,
                   'portals': self._s2d(portals)}
        self.nef.targets.create(payload)

    def _get_host_group(self, member):
        """Find existing host group by group member.

        :param member: host group member
        :returns: host group name
        """
        host_groups = self.nef.hostgroups.list()
        for host_group in host_groups:
            members = host_group['members']
            if member in members:
                name = host_group['name']
                LOG.debug('Found host group %(name)s for member %(member)s',
                          {'name': name, 'member': member})
                return name
        return None

    def _create_host_group(self, name, members):
        """Create a new host group.

        :param name: host group name
        :param members: host group members list
        """
        payload = {'name': name, 'members': members}
        self.nef.hostgroups.create(payload)

    @staticmethod
    def _s2d(css):
        """Parse list of colon-separated address and port to dictionary.

        :param css: list of colon-separated address and port
        :returns: dictionary
        """
        result = []
        for key_val in css:
            key, val = key_val.split(':')
            result.append({'address': key, 'port': int(val)})
        return result

    @staticmethod
    def _d2s(kvp):
        """Parse dictionary to list of colon-separated address and port.

        :param kvp: dictionary
        :returns: list of colon-separated address and port
        """
        result = []
        for key_val in kvp:
            result.append('%s:%s' % (key_val['address'], key_val['port']))
        return result

    @coordination.synchronized('{self.lock}')
    def _delete_snapshot(self, path, recursive=False, defer=True):
        """Deletes a snapshot.

        :param path: absolute snapshot path
        :param recursive: boolean, True to recursively destroy snapshots
                          of the same name on a child datasets
        :param defer: boolean, True to mark the snapshot for deferred
                      destroy when there are not any active references
                      to it (for example, clones)
        """
        payload = {'recursive': recursive, 'defer': defer}
        self.nef.snapshots.delete(path, payload)

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
