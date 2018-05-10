"""Classes used in the main application."""
from uuid import uuid4

import json
import requests
from datetime import datetime

from kytos.core import log
from kytos.core.helpers import now, get_time
from kytos.core.interface import UNI, TAG
from napps.kytos.mef_eline import settings


class EVC:
    """Class that represents a E-Line Virtual Connection."""


    def __init__(self, *args, **kwargs):
        """Create an EVC instance with the provided parameters.

        Do some basic validations to attributes.
        """
        self.validate(*args, **kwargs)
        self.fill_attributes(*args,**kwargs)

    def fill_attributes(self, *args, **kwargs):
        """Fill all attributes given in the EVC object."""
        for attribute, default in self.default_attributes.items():
            value = kwargs.get(attribute, default)

            if attribute == '_id':
                value = kwargs.get('id', default)

            elif 'time' in attribute or 'date' in attribute:
                if isinstance(value, str) or isinstance(value, dict):
                    value = get_time(value)

            setattr(self, attribute, value)

    @property
    def default_attributes(self):
        """Default attributes in the EVC object."""
        return {
                '_id': uuid4().hex,
                'name': None,
                'uni_a': None,
                'uni_z': None,
                'start_date': now(),
                'end_date': None,
                # Bandwidth profile
                'bandwidth': None,
                'primary_links': None,
                'backup_links': None,
                'dynamic_backup_path': None,
                # dict with the user original request (input)
                '_requested': {},
                # circuit being used at the moment if this is an active circuit
                'current_path': [],
                # primary circuit offered to user IF one or more links were
                # provided in the request
                'primary_path': [],
                # backup circuit offered to the user IF one or more links were
                # provided in the request
                'backup_path': [],
                # datetime of user request for a EVC (or datetime when object
                # was created)
                'request_time': now(),
                # datetime when the circuit should be activated.
                # now() || schedule()
                'creation_time': now(),
                # Operational State
                'active': False,
                # Administrative State
                'enabled': False,
                # Service level provided in the request. "Gold", "Silver", ...
                'priority': 0,
               }

    @property
    def required_attributes(self):
        """Required attributes in the EVC object."""
        return ['name', 'uni_a', 'uni_z']

    def validate(self, *args, **kwargs):
        """Validate the arguments.

        Raises:
            TypeError: Rases an error if the error message.
        """
        for attribute in self.required_attributes:
            if attribute not in kwargs.keys():
                raise TypeError(f"{attribute} is required.")
            if 'uni' in attribute:
                uni = kwargs.get(attribute)
                if not isinstance(uni, UNI):
                    raise TypeError(f"Invalid UNI: {attribute}.")
                if not uni.is_valid():
                    raise TypeError("Invalid UNI {attribute}.")

    def as_dict(self):
        """Dict representation for the EVC object."""
        evc_dict = {}

        for attribute in self.default_attributes:
            if '_id' in attribute:
                evc_dict['id'] = getattr(self, attribute)
            elif 'time' in attribute or 'date' in attribute:
                value = getattr(self, attribute)
                if value:
                    evc_dict[attribute] = value.strftime("%Y-%m-%dT%H:%M:%S")
            elif 'uni' in attribute:
                uni = getattr(self, attribute)
                evc_dict[attribute] = uni.as_dict()
            else:
                evc_dict[attribute] = getattr(self, attribute)
        return evc_dict

    def as_json(self):
        """Json representation for the EVC object."""
        return json.dumps(self.as_dict())

    @property
    def id(self):  # pylint: disable=invalid-name
        """Return this EVC's ID."""
        return self._id

    def create(self):
        pass

    def discover_new_path(self):
        pass

    def change_path(self, path):
        pass

    def reprovision(self):
        """Force the EVC (re-)provisioning"""
        pass

    def remove(self):
        pass

    @staticmethod
    def send_flow_mods(switch, flow_mods):
        """Send a flow_mod list to a specific switch."""
        endpoint = "%s/flows/%s" % (settings.MANAGER_URL, switch.id)

        data = {"flows": flow_mods}
        requests.post(endpoint, json=data)

    @staticmethod
    def prepare_flow_mod(in_interface, out_interface, in_vlan=None,
                         out_vlan=None, push=False, pop=False, change=False):
        """Create a flow_mod dictionary with the correct parameters."""
        default_action = {"action_type": "output",
                          "port": out_interface.port_number}

        flow_mod = {"match": {"in_port": in_interface.port_number},
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

    def deploy(self):
        """Install the flows for this circuit."""
        if self.primary_links is None:
            log.info("Primary links are empty.")
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

        log.info(f"The circuit {self.id} was deployed.")
