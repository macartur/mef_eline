"""Module to test the main napp file."""
from unittest import TestCase
from unittest.mock import MagicMock, PropertyMock, patch
import json

from tests.helper import (get_app_test_client, get_event_listeners,
                          get_controller_mock, get_napp_urls)

# import NAppMain
from napps.kytos.mef_eline.main import Main


class TestMain(TestCase):
    """Test the Main class."""

    def setUp(self):
        """Execute steps before each tests.

        Set the server_name_url_url from kytos/mef_eline
        """
        self.server_name_url = 'http://localhost:8181/api/kytos/mef_eline'
        self.napp = Main(get_controller_mock())

    def test_get_event_listeners(self):
        """Verify all event listeners registered."""
        expected_events = ['kytos/core.shutdown',
                           'kytos/core.shutdown.kytos/mef_eline',
                           'kytos/topology.updated']
        actual_events = get_event_listeners(self.napp)
        self.assertEqual(expected_events, actual_events)

    def test_verify_api_urls(self):
        """Verify all APIs registered."""
        expected_urls = [
            ({}, {'OPTIONS', 'POST'},
             '/api/kytos/mef_eline/v2/evc/'),
            ({}, {'OPTIONS', 'HEAD', 'GET'},
             '/api/kytos/mef_eline/v2/evc/'),
            ({'circuit_id': '[circuit_id]'}, {'OPTIONS', 'HEAD', 'GET'},
             '/api/kytos/mef_eline/v2/evc/<circuit_id>'),
            ({'circuit_id': '[circuit_id]'}, {'OPTIONS', 'PATCH'},
             '/api/kytos/mef_eline/v2/evc/<circuit_id>')]
        urls = get_napp_urls(self.napp)
        self.assertEqual(expected_urls, urls)

    def test_list_circuits_without_circuits(self):
        """Test if list_circuits return expected result without circuits."""
        api = get_app_test_client(self.napp)
        url = f'{self.server_name_url}/v2/evc/'
        response = api.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.data.decode()),
                         {"response": "No circuit stored."})

    def test_list_circuits_with_circuits_stored(self):
        """Test if list circuits return all circuts registered."""
        circuits = { '1': { 'name': 'circuit_1'},
                     '2': {'name': 'circuit_2'}}
        self.napp.box = MagicMock()
        self.napp.box.data = circuits

        api = get_app_test_client(self.napp)
        url = f'{self.server_name_url}/v2/evc/'

        response = api.get(url)
        expected_result = circuits
        self.assertEqual(json.loads(response.data), expected_result)


    def test_get_circuit_by_valid_circuit_id(self):
        """Test if get_cirguit return the ciruit attributes."""
        circuits = {'1': { 'name': 'circuit_1'},
                    '2': {'name': 'circuit_2'}}
        self.napp.box = MagicMock()
        self.napp.box.data = circuits

        api = get_app_test_client(self.napp)
        url = f'{self.server_name_url}/v2/evc/1'
        response = api.get(url)
        expected_result = circuits['1']
        self.assertEqual(json.loads(response.data), expected_result)

    def test_get_circuit_by_invalid_circuit_id(self):
        """Test if get_circuit return invalid circuit_id"""
        circuits = {'1': { 'name': 'circuit_1'},
                    '2': {'name': 'circuit_2'}}
        self.napp.box = MagicMock()
        self.napp.box.data = circuits

        api = get_app_test_client(self.napp)
        url = f'{self.server_name_url}/v2/evc/3'
        response = api.get(url)
        expected_result = {'response': 'circuit_id 3 not found'}
        self.assertEqual(json.loads(response.data), expected_result)

    @patch('napps.kytos.mef_eline.scheduler.Scheduler.add')
    @patch('napps.kytos.mef_eline.main.Main.uni_from_dict')
    @patch('napps.kytos.mef_eline.main.Main.get_best_path')
    @patch('napps.kytos.mef_eline.main.Main.save_evc')
    @patch('napps.kytos.mef_eline.main.EVC.as_dict')
    @patch('napps.kytos.mef_eline.models.EVC._validate')
    def test_create_a_circuit(self, validate_mock, evc_as_dict_mock,
                              save_evc_mock, get_best_path_mock,
                              uni_from_dict_mock, sched_add_mock):
        """Test create a new circuit."""
        validate_mock.return_value = True
        save_evc_mock.return_value = True
        uni_from_dict_mock.side_effect = ['uni_a', 'uni_z']
        get_best_path_mock.return_value = True
        evc_as_dict_mock.return_value = {}
        sched_add_mock.return_value = True


        # the circuit saved is  empty.
        self.napp.box = MagicMock()
        self.napp.box.data = {}

        api = get_app_test_client(self.napp)
        url = f'{self.server_name_url}/v2/evc/'
        payload = {
                   "name": "my evc1",
                   "frequency": "* * * * *",
                   "uni_a": {
                     "interface_id": "00:00:00:00:00:00:00:01:1",
                     "tag": {
                       "tag_type": 1,
                       "value": 80
                     }
                   },
                   "uni_z": {
                     "interface_id": "00:00:00:00:00:00:00:02:2",
                     "tag": {
                       "tag_type": 1,
                       "value": 1
                     }
                   }
                 }

        response = api.post(url, json=payload)
        current_data = json.loads(response.data)

        # verify expected result from request
        self.assertEqual(201, response.status_code)
        self.assertIn('circuit_id', current_data)

        # verify uni called
        uni_from_dict_mock.called_twice
        uni_from_dict_mock.assert_any_call(payload['uni_z'])
        uni_from_dict_mock.assert_any_call(payload['uni_a'])

        # verify validation called
        validate_mock.assert_called_once()
        validate_mock.assert_called_with(frequency='* * * * *',
                                         name='my evc1',
                                         uni_a='uni_a',
                                         uni_z='uni_z')
        # verify save method is called
        save_evc_mock.assert_called_once()

        # verify get_best_path is called
        get_best_path_mock.assert_called_once()
        # verify evc as dict is called to save in the box
        evc_as_dict_mock.assert_called_once()
        # verify add circuit in sched
        sched_add_mock.assert_called_once()
