"""Module to test the schedule.py file."""
import sys
from unittest import TestCase
from unittest.mock import Mock

from kytos.core.interface import TAG, UNI, Interface
from kytos.core.switch import Switch
from kytos.core.link import Link

# pylint: disable=wrong-import-position
sys.path.insert(0, '/var/lib/kytos/napps/..')
# pylint: enable=wrong-import-position

from napps.kytos.mef_eline.models import EVC  # NOQA


class TestEVC(TestCase):
    """Tests to verify EVC class."""

    def test_attributes_empty(self):
        """Test if the EVC raises an error with name is required."""
        attributes = {}
        error_message = "name is required."
        with self.assertRaises(ValueError) as handle_error:
            EVC(**attributes)
        self.assertEqual(str(handle_error.exception), error_message)

    def test_without_uni_a(self):
        """Test if the EVC raises and error with UNI A is required."""
        attributes = {"name": "circuit_name"}
        error_message = "uni_a is required."
        with self.assertRaises(ValueError) as handle_error:
            EVC(**attributes)
        self.assertEqual(str(handle_error.exception), error_message)

    def test_with_invalid_uni_a(self):
        """Test if the EVC raises and error with invalid UNI A."""
        attributes = {
            "name": "circuit_name",
            "uni_a": self.get_uni_mocked(tag_value=82)
        }
        error_message = "VLAN tag 82 is not available in uni_a"
        with self.assertRaises(ValueError) as handle_error:
            EVC(**attributes)
        self.assertEqual(str(handle_error.exception), error_message)

    def test_without_uni_z(self):
        """Test if the EVC raises and error with UNI Z is required."""
        attributes = {
            "name": "circuit_name",
            "uni_a": self.get_uni_mocked(is_valid=True)
        }
        error_message = "uni_z is required."
        with self.assertRaises(ValueError) as handle_error:
            EVC(**attributes)
        self.assertEqual(str(handle_error.exception), error_message)

    def test_with_invalid_uni_z(self):
        """Test if the EVC raises and error with UNI Z is required."""
        attributes = {
            "name": "circuit_name",
            "uni_a": self.get_uni_mocked(is_valid=True),
            "uni_z": self.get_uni_mocked(tag_value=83)
        }
        error_message = "VLAN tag 83 is not available in uni_z"
        with self.assertRaises(ValueError) as handle_error:
            EVC(**attributes)
        self.assertEqual(str(handle_error.exception), error_message)

    @staticmethod
    def get_uni_mocked(**kwargs):
        """Create an uni mocked.

        Args:
            interface_name(str): Interface name. Defaults to "eth1".
            interface_port(int): Interface pror. Defaults to 1.
            tag_type(int): Type of a tag. Defaults to 1.
            tag_value(int): Value of a tag. Defaults to 81
            is_valid(bool): Value returned by is_valid method.
                            Defaults to False.
        """
        interface_name = kwargs.get("interface_name", "eth1")
        interface_port = kwargs.get("interface_port", 1)
        tag_type = kwargs.get("tag_type", 1)
        tag_value = kwargs.get("tag_value", 81)
        is_valid = kwargs.get("is_valid", False)

        interface = Interface(interface_name, interface_port,
                              Mock(spec=Switch))
        tag = TAG(tag_type, tag_value)
        uni = Mock(spec=UNI, interface=interface, user_tag=tag)
        uni.is_valid.return_value = is_valid
        uni.as_dict.return_value = {
            "interface_id": f'switch_mock:{interface_port}',
            "tag": tag.as_dict()
        }
        return uni

    @staticmethod
    def get_link_mocked(**kwargs):
        """Return a link mocked.

        Args:
            link_dict: Python dict returned after call link.as_dict()
        """
        link = Mock(spec=Link)
        link.as_dict.return_value = kwargs.get('link_dict', {"id": "link_id"})
        return link

    def test_update_name(self):
        """Test if raises and error when trying to update the name."""
        attributes = {
            "name": "circuit_name",
            "uni_a": self.get_uni_mocked(is_valid=True),
            "uni_z": self.get_uni_mocked(is_valid=True)
        }
        update_dict = {
            "name": "circuit_name_2"
        }
        error_message = "name can't be be updated."
        with self.assertRaises(ValueError) as handle_error:
            evc = EVC(**attributes)
            evc.update(**update_dict)
        self.assertEqual(str(handle_error.exception), error_message)

    def test_update_uni_a(self):
        """Test if raises and error when trying to update the uni_a."""
        attributes = {
            "name": "circuit_name",
            "uni_a": self.get_uni_mocked(is_valid=True),
            "uni_z": self.get_uni_mocked(is_valid=True)
        }
        update_dict = {
            "uni_a": self.get_uni_mocked(is_valid=True)
        }
        error_message = "uni_a can't be be updated."
        with self.assertRaises(ValueError) as handle_error:
            evc = EVC(**attributes)
            evc.update(**update_dict)
        self.assertEqual(str(handle_error.exception), error_message)

    def test_update_uni_z(self):
        """Test if raises and error when trying to update the uni_z."""
        attributes = {
            "name": "circuit_name",
            "uni_a": self.get_uni_mocked(is_valid=True),
            "uni_z": self.get_uni_mocked(is_valid=True)
        }
        update_dict = {
            "uni_z": self.get_uni_mocked(is_valid=True)
        }
        error_message = "uni_z can't be be updated."
        with self.assertRaises(ValueError) as handle_error:
            evc = EVC(**attributes)
            evc.update(**update_dict)
        self.assertEqual(str(handle_error.exception), error_message)

    def test_circuit_representation(self):
        """Test the method __repr__."""
        attributes = {
            "name": "circuit_name",
            "uni_a": self.get_uni_mocked(is_valid=True),
            "uni_z": self.get_uni_mocked(is_valid=True)
        }
        evc = EVC(**attributes)
        expected_value = f'EVC({evc.id}, {evc.name})'
        self.assertEqual(str(evc), expected_value)

    def test_comparison_method(self):
        """Test the method __eq__."""
        attributes = {
            "name": "circuit_name",
            "uni_a": self.get_uni_mocked(is_valid=True),
            "uni_z": self.get_uni_mocked(is_valid=True)
        }
        evc1 = EVC(**attributes)
        evc2 = EVC(**attributes)

        attributes = {
            "name": "circuit_name_2",
            "uni_a": self.get_uni_mocked(is_valid=True),
            "uni_z": self.get_uni_mocked(is_valid=True)
        }
        evc3 = EVC(**attributes)
        evc4 = EVC(**attributes)

        self.assertEqual(evc1 == evc2, True)
        self.assertEqual(evc1 == evc3, False)
        self.assertEqual(evc2 == evc3, False)
        self.assertEqual(evc3 == evc4, True)

    def test_as_dict_method(self):
        """Test the method as_dict."""
        attributes = {
            "id": "custom_id",
            "name": "custom_name",
            "uni_a": self.get_uni_mocked(is_valid=True),
            "uni_z": self.get_uni_mocked(is_valid=True),
            "start_date": '2018-08-21T18:44:54',
            "end_date": '2018-08-21T18:44:55',
            'primary_links': [],
            'request_time': '2018-08-21T19:10:41',
            'creation_time': '2018-08-21T18:44:54',
            'owner': "my_name",
            'circuit_scheduler': [],
            'enabled': True,
            'priority': 2
        }
        evc = EVC(**attributes)

        expected_dict = {
            'id': 'custom_id',
            'name': 'custom_name',
            'uni_a': attributes['uni_a'].as_dict(),
            'uni_z': attributes['uni_z'].as_dict(),
            'start_date': '2018-08-21T18:44:54',
            'end_date': '2018-08-21T18:44:55',
            'bandwidth': 0,
            'primary_links': [],
            'backup_links': [],
            'current_path': [],
            'primary_path': [],
            'backup_path': [],
            'dynamic_backup_path': False,
            '_requested': {
                           "id": "custom_id",
                           "name": "custom_name",
                           "uni_a": attributes['uni_a'].as_dict(),
                           "uni_z": attributes['uni_z'].as_dict(),
                           "start_date": '2018-08-21T18:44:54',
                           "end_date": '2018-08-21T18:44:55',
                           'primary_links': [],
                           'request_time': '2018-08-21T19:10:41',
                           'creation_time': '2018-08-21T18:44:54',
                           'owner': "my_name",
                           'circuit_scheduler': [],
                           'enabled': True,
                           'priority': 2
            },
            'request_time': '2018-08-21T19:10:41',
            'creation_time': '2018-08-21T18:44:54',
            'owner': 'my_name',
            'circuit_scheduler': [],
            'active': False,
            'enabled': True,
            'priority': 2
        }
        actual_dict = evc.as_dict()
        for name, value in expected_dict.items():
            actual = actual_dict.get(name)
            if name == '_requested':
                for requested_name, requested_value in value.items():
                    if isinstance(requested_value, UNI):
                        value[requested_name] = requested_value.as_dict()
            self.assertEqual(value, actual)
