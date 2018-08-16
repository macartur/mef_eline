"""Classes used in the main application."""
from uuid import uuid4

import requests
from datetime import datetime
from kytos.core import log
from kytos.core.helpers import now, get_time
from kytos.core.interface import UNI
from kytos.core.common import GenericEntity, EntityStatus
from napps.kytos.mef_eline import settings

class EVC(GenericEntity):
    """Class that represents a E-Line Virtual Connection."""

    def __init__(self, **kwargs):
        """Create an EVC instance with the provided parameters.

        Args:
            id(str): EVC identifier. Whether it's None an ID will be genereted.
            name: represents an EVC name.(Required)
            uni_a (UNI): Endpoint A for User Network Interface.(Required)
            uni_z (UNI): Endpoint Z for User Network Interface.(Required)
            start_date(datetime|str): Date when the EVC was registred.
                                      Default is now().
            end_date(datetime|str): Final date that the EVC will be fineshed.
                                    Default is None.
            bandwidth(int): Bandwidth used by EVC instance. Default is 0.
            primary_links(list): Primary links used by evc. Default is []
            backup_links(list): Backups links used by evc. Default is []
            current_path(list): Circuit being used at the moment if this is an
                                active circuit. Default is [].
            primary_path(list): primary circuit offered to user IF one or more
                                links were provided. Default is [].
            backup_path(list): backup circuit offered to the user IF one or
                               more links were provided. Default is [].
            dynamic_backup_path(bool): Enable computer backup path dynamically.
                                       Dafault is False.
            creation_time(datetime|str): datetime when the circuit should be
                                         activated. default is now().
            enabled(Boolean): attribute to indicate the operational state.
                              default is False.
            active(Boolean): attribute to Administrative state;
                             default is False.
            owner(str): The EVC owner. Default is None.
            priority(int): Service level provided in the request. Default is 0.

        Raises:
            ValueError: raised when object attributes are invalid.
        """
        self._validate(**kwargs)
        super().__init__()

        # required attributes
        self._id = kwargs.get('id', uuid4().hex)
        self.uni_a = kwargs.get('uni_a')
        self.uni_z = kwargs.get('uni_z')
        self.name = kwargs.get('name')

        # optional attributes
        self.start_date = get_time(kwargs.get('start_date')) or now()
        self.end_date = get_time(kwargs.get('end_date')) or None

        self.bandwidth = kwargs.get('bandwidth', 0)
        self.primary_links = kwargs.get('primary_links', [])
        self.backup_links =  kwargs.get('backup_links', [])
        self.current_path = kwargs.get('current_path', [])
        self.primary_path = kwargs.get('primary_path', [])
        self.backup_path = kwargs.get('backup_path', [])
        self.dynamic_backup_path = kwargs.get('dynamic_backup_path', False)
        self.creation_time = get_time(kwargs.get('creation_time')) or  now()
        self.owner = kwargs.get('owner', None)
        self.priority = kwargs.get('priority', 0)

        self.current_links_cache = set()
        self.primary_links_cache = set()
        self.backup_links_cache = set()

        if kwargs.get('active', False):
            self.activate()
        else:
            self.deactivate()

        if kwargs.get('enabled', False):
            self.enable()
        else:
            self.disable()

        # datetime of user request for a EVC (or datetime when object was
        # created)
        self.request_time = now()
        # dict with the user original request (input)
        self._requested = kwargs

    def __repr__(self):
        """Repr method."""
        return f"EVC({self._id}, {self.name})"

    def _validate(self, **kwargs):
        """Do Basic validations.

        Verify required attributes: name, uni_a, uni_z
        Verify if the attributes uni_a and uni_z are valid.

        Raises:
            ValueError: message with error detail.

        """
        required_attributes = ['name', 'uni_a', 'uni_z']

        for attribute in required_attributes:

            if attribute not in kwargs:
                raise ValueError(f'{attribute} is required.')

            if 'uni' in attribute:
                uni = kwargs.get(attribute)

                if not isinstance(uni, UNI):
                    raise ValueError(f'{attribute} is an invalid UNI.')

                elif not uni.is_valid():
                    tag = uni_a.user_tag.value
                    message = f'VLAN tag {tag} is not available in {attribute}'
                    raise ValueError(message)

    def __eq__(self, other):
        """Override the default implementation."""
        if not isinstance(other, EVC):
            return False

        attrs_to_compare = ['name', 'uni_a', 'uni_z', 'owner', 'bandwidth']
        for attribute in attrs_to_compare:
            if getattr(other, attribute) != getattr(self, attribute):
                return False
        return True

    def as_dict(self):
        """A dictionary representing an EVC object."""
        evc_dict = {"id": self.id, "name": self.name,
                    "uni_a": self.uni_a.as_dict(),
                    "uni_z": self.uni_z.as_dict()}

        time_fmt = "%Y-%m-%dT%H:%M:%S"

        def link_as_dict(links):
            """Return list comprehension of links as_dict."""
            return [link.as_dict() for link in links if link]

        evc_dict["start_date"] = self.start_date
        if isinstance(self.start_date, datetime):
            evc_dict["start_date"] = self.start_date.strftime(time_fmt)

        evc_dict["end_date"] = self.end_date
        if isinstance(self.end_date, datetime):
            evc_dict["end_date"] = self.end_date.strftime(time_fmt)

        evc_dict['bandwidth'] = self.bandwidth
        evc_dict['primary_links'] = link_as_dict(self.primary_links)
        evc_dict['backup_links'] = link_as_dict(self.backup_links)
        evc_dict['current_path'] = link_as_dict(self.current_path)
        evc_dict['primary_path'] = link_as_dict(self.primary_path)
        evc_dict['backup_path'] = link_as_dict(self.backup_path)
        evc_dict['dynamic_backup_path'] = self.dynamic_backup_path

        if self._requested:
            request_dict = self._requested.copy()
            request_dict['uni_a'] = request_dict['uni_a'].as_dict()
            request_dict['uni_z'] = request_dict['uni_z'].as_dict()
            evc_dict['_requested'] = request_dict

        time = self.request_time.strftime(time_fmt)
        evc_dict['request_time'] = time

        time = self.creation_time.strftime(time_fmt)
        evc_dict['creation_time'] = time

        evc_dict['owner'] = self.owner
        evc_dict['active'] = self.is_active()
        evc_dict['enabled'] = self.is_enabled()
        evc_dict['priority'] = self.priority

        return evc_dict

    def create(self):
        pass

    def discover_new_path(self):

    def _get_paths(self):
        """Get a valid path for the circuit from the Pathfinder."""
        endpoint = settings.PATHFINDER_URL
        request_data = {"source": self.uni_a.interface.id,
                        "destination": self.uni_z.interface.id}
        api_reply = requests.post(endpoint, json=request_data)
        if api_reply.status_code != requests.codes.ok:
            log.error("Failed to get paths at %s. Returned %s",
                      endpoint, api_reply.status_code)
            return None

        reply_data = api_reply.json()
        return reply_data.get('paths')

    def _get_best_path(self):
        """Return the best path available for a circuit, if exists."""
        paths = self._get_paths()
        if paths:
            return self.create_path(paths[0]['hops'])

    @staticmethod
    def _clear_path(path):
        """Remove switches from a path, returning only interfaeces."""
        return [endpoint for endpoint in path if len(endpoint) > 23]

    TODO: continuar aqui......

#    def change_path(self, path):
#        pass

#    def reprovision(self):
#        """Force the EVC (re-)provisioning"""
#        if self.backup_path.is_set() and self.backup_path.is_up():
#            # EVC has a backup_path set by user and it is up
#            self.move_to_backup_path()
#        elif self.dynamic_backup_path:
#            # Search for a dynamic path
#            self.discover_new_path()
# TODO: Create a __hash__ on Link
# TODO: Fix flapping links

# EVENTS:
#   LINK_DOWN: Network Problem (Operations)
#   LINK_UNDER_MAINTENANCE: Administrative down (Administrative)
#
# Operations

# link.activate()
# link.deactivate()

# Administative

# link.enable()
# link.disable()

# Questions:
# link.is_active()
# link.is_enabled()
# link.is_administrative_down()

    # TODO: Double check if those events are correct
    # TODO: We need to generate a new event to maintenance operations
    @listen('kytos.*.link.down')
    @listen('kytos.*.link.under_maintenance')
    def handle_link_down(self, event):
        if not self.is_enabled() or not self.is_affected_by_link(event.link):
            return False

        success = False
        if self.is_using_primary_path():
            success = self.deploy_to_backup_path()
        elif self.is_using_backup_path():
            success = self.deploy_to_primary_path()

        if success:
            # TODO: LOG/EVENT: Circuit deployed after link down
            return success

        if self.dynamic_backup_path:
            success = self.deploy()
            # TODO: LOG/EVENT: failed to re-deploy circuit after link down
            return success

    @listen('kytos.*.link.up')
    @listen('kytos.*.link.end_maintenance')
    def handle_link_up(self, event):
        if not self.is_enabled():
            return True

        if self.is_using_primary_path() and \
           self.get_path_status(self.primary_path) == EntityStatus.UP:
            return True

        success = False
        if self.is_primary_path_affected_by_link(event.link):
            success = self.deploy(self.primary_path)

        if success:
            return True

        # TODO: Question: If the current circuit is dynamic and backup is
        # defined and working, should I try to deploy(backup)?

        # We tried to deploy(primary_path) without success.
        # And in this case is up by some how. Nothing to do.
        if self.is_using_backup_path() or self.is_using_dynamic_path():
            return True

        # In this case, probably the circuit is not being used and
        # we can move to backup
        if self.is_backup_path_affected_by_link(event.link):
            success = self.deploy(self.backup_path)

        if success:
            return True

        # In this case, the circuit is not being used and we should
        # try a dynamic path
        if self.dynamic_backup_path:
            return self.deploy()

        return True

    def is_affected_by_link(self, link):
        return link in self.current_path_cache

    def is_backup_path_affected_by_link(self, link):
        return link in self.backup_path_cache

    def is_primary_path_affected_by_link(self, link):
        return link in self.primary_path_cache

    def is_using_primary_path(self):
        """Verify if the current deployed path is self.primary_path."""
        return self.current_path == self.primary_path

    def is_using_backup_path(self):
        """Verify if the current deployed path is self.backup_path."""
        return self.current_path == self.backup_path

    def is_using_dynamic_path(self):
        """Verify if the current deployed path is a dynamic path."""
        if not self.is_using_primary_path() and \
           not self.is_using_backup_path() and \
           self.get_path_status(self.current_path) == EntityStatus.UP:
               return True
        return False

    def deploy_to_backup_path(self):
        """Deploy the backup path into the datapaths of this circuit.

        If the backup_path attribute is valid and up, this method will try to
        deploy this backup_path.

        If everything fails and dynamic_backup_path is True, then tries to
        deploy a dynamic path.
        """
        if self.is_using_backup_path:
            # TODO: Log to say that cannot move backup to backup
            return True

        success = False
        if self.get_path_status(self.backup_path) is EntityStatus.UP:
            success = self.deploy(self.backup_path)

        if success:
            return True

        if self.dynamic_backup_path:
            return self.deploy()

        return False

    def deploy_to_primary_path(self):
        """Deploy the primary path into the datapaths of this circuit.

        If the primary_path attribute is valid and up, this method will try to
        deploy this primary_path.
        """
        if self.is_using_primary_path():
            # TODO: Log to say that cannot move primary to primary
            return False

        if self.get_path_status(self.primary_path) is EntityStatus.UP:
            return self.deploy(self.primary_path)
        return False

    def get_path_status(self, path):
        """Check for the current status of a path.

        If any link in this path is down, the path is considered down.
        """
        if not path:
            return EntityStatus.DISABLED

        for link in path:
            if link.status is not EntityStatus.UP:
                return link.status
        return EntityStatus.UP

    def remove_current_flows(self):
        """Remove all flows from current path."""
        switches = set()

        for link from self.current_path:
            switches.add(link.endpoint_a.switch)
            switches.add(link.endpoint_b.switch)

        flows = [{'cookie': self.get_cookie()}]
        for switch in switches:
            self.send_flow_mods(switch, flows, 'delete')

        self.deactivate()

    def remove(self):
        pass

    @property
    def id(self):  # pylint: disable=invalid-name
        """Return this EVC's ID."""
        return self._id

    @staticmethod
    def send_flow_mods(switch, flow_mods, command='flows'):
        """Send a flow_mod list to a specific switch."""
        endpoint = "%s/%s/%s" % (settings.MANAGER_URL, command,switch.id)
        data = {"flows": flow_mods}
        requests.post(endpoint, json=data)

    def get_cookie(self):
        """Return the cookie integer from evc id."""
        value = self.id[len(self.id)//2:]
        return int(value, 16)

    @staticmethod
    def prepare_flow_mod(in_interface, out_interface, in_vlan=None,
                         out_vlan=None, push=False, pop=False, change=False):
        """Create a flow_mod dictionary with the correct parameters."""
        default_action = {"action_type": "output",
                          "port": out_interface.port_number}

        flow_mod = {"match": {"in_port": in_interface.port_number},
                    "cookie": self.get_cookie(),
                    "actions": [default_action]}
        if in_vlan:
            flow_mod['match']['dl_vlan'] = in_vlan
        if out_vlan and not pop:
            new_action = {"action_type": "set_vlan",
                          "vlan_id": out_vlan}
            flow_mod["actions"].insert(0, new_action)
        if pop:
            new_action = {"action_type": "pop_vlan"}
            flow_mod["actions"].insert(0, new_action)
        if push:
            new_action = {"action_type": "push_vlan",
                          "tag_type": "s"}
            flow_mod["actions"].insert(0, new_action)
        if change:
            new_action = {"action_type": "set_vlan",
                          "vlan_id": change}
            flow_mod["actions"].insert(0, new_action)
        return flow_mod

    def _chose_vlans(self):
        """Chose the VLANs to be used for the circuit."""
        for link in self.primary_links:
            tag = link.get_next_available_tag()
            link.use_tag(tag)
            link.add_metadata('s_vlan', tag)

    def primary_links_zipped(self):
        """Return an iterator which yields pairs of links in order."""
        return zip(self.primary_links[:-1],
                   self.primary_links[1:])

    def deploy(self, path=None):
        """Install the flows for this circuit."""
        # TODO: Refact this in case path is None
        #
        # 0. Remove current flows installed
        # 1. Decide if will deploy "path" or discover a new path
        # 2. Choose vlans
        # 3. Install NNI flows
        # 4. Install UNI flows
        # 5. Activate
        # 6. Update current_path
        # 7. Update links caches (primary, current, backup)

        self.remove_current_flows()

        if path is None:
            path = self.discover_new_path()
            return False

        self._chose_vlans()

        # Install NNI flows
        for incoming, outcoming in self.primary_links_zipped():
            in_vlan = incoming.get_metadata('s_vlan').value
            out_vlan = outcoming.get_metadata('s_vlan').value

            flows = []
            # Flow for one direction
            flows.append(self.prepare_flow_mod(incoming.endpoint_b,
                                               outcoming.endpoint_a,
                                               in_vlan, out_vlan))

            # Flow for the other direction
            flows.append(self.prepare_flow_mod(outcoming.endpoint_a,
                                               incoming.endpoint_b,
                                               out_vlan, in_vlan))

            self.send_flow_mods(incoming.endpoint_b.switch, flows)

        # Install UNI flows
        # Determine VLANs
        in_vlan_a = self.uni_a.user_tag.value if self.uni_a.user_tag else None
        out_vlan_a = self.primary_links[0].get_metadata('s_vlan').value

        in_vlan_z = self.uni_z.user_tag.value if self.uni_z.user_tag else None
        out_vlan_z = self.primary_links[-1].get_metadata('s_vlan').value

        # Flows for the first UNI
        flows_a = []

        # Flow for one direction, pushing the service tag
        flows_a.append(self.prepare_flow_mod(self.uni_a.interface,
                                             self.primary_links[0].endpoint_a,
                                             in_vlan_a, out_vlan_a, True,
                                             change=in_vlan_z))

        # Flow for the other direction, popping the service tag
        flows_a.append(self.prepare_flow_mod(self.primary_links[0].endpoint_a,
                                             self.uni_a.interface,
                                             out_vlan_a, in_vlan_a, pop=True))

        self.send_flow_mods(self.uni_a.interface.switch, flows_a)

        # Flows for the second UNI
        flows_z = []

        # Flow for one direction, pushing the service tag
        flows_z.append(self.prepare_flow_mod(self.uni_z.interface,
                                             self.primary_links[-1].endpoint_b,
                                             in_vlan_z, out_vlan_z, True,
                                             change=in_vlan_a))

        # Flow for the other direction, popping the service tag
        flows_z.append(self.prepare_flow_mod(self.primary_links[-1].endpoint_b,
                                             self.uni_z.interface,
                                             out_vlan_z, in_vlan_z, pop=True))

        self.send_flow_mods(self.uni_z.interface.switch, flows_z)

        self.activate()
        log.info(f"{self} was deployed.")
