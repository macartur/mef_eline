"""Module to test the main napp file."""
from unittest import TestCase

from tests.helper import (get_app_test_client, get_event_listeners,
                          get_napp_urls)


class TestMain(TestCase):
    """Test the Main class."""

    def setUp(self):
        """Execute steps before each tests.

        Set the server_name_url_url from kytos/mef_eline
        """
        self.server_name_url = 'http://localhost:8181/api/kytos/mef_eline'

    def test_get_event_listeners(self):
        """Verify all event listeners registered."""
        expected_events = ['kytos/core.shutdown',
                           'kytos/core.shutdown.kytos/mef_eline',
                           'kytos/topology.updated']
        actual_events = get_event_listeners()
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
        urls = get_napp_urls()
        self.assertEqual(expected_urls, urls)

    def test_list_circuits(self):
        """Test if list_circuits return all circuits registered."""
        api = get_app_test_client()
        url = f'{self.server_name_url}/v2/evc/'
        result = api.get(url)
        self.assertEqual(200, result.status_code)
