"""Module to help create tests."""
import sys
from unittest.mock import Mock

# import the controller
from kytos.core import Controller
from kytos.core.config import KytosConfig
# import the napps path
sys.path.insert(0, '/var/lib/kytos/napps/..')

# import NAppMain
from napps.kytos.mef_eline.main import Main


def get_controller_mock():
    """Return a controller mock."""
    options = KytosConfig().options['daemon']
    controller = Controller(options)
    controller.log = Mock()
    return controller


def get_napp_urls(username='kytos', napp_name='mef_eline'):
    """Return the kytos/mef_eline urls.

    The urls will be like:

    urls = [
        (options, methods, url)
    ]

    """
    controller = get_controller_mock()
    napp = Main(controller)

    controller.api_server.register_napp_endpoints(napp)
    urls = []
    for rule in controller.api_server.app.url_map.iter_rules():
        options = {}
        for arg in rule.arguments:
            options[arg] = "[{0}]".format(arg)

        if f'{username}/{napp_name}' in str(rule):
            urls.append((options, rule.methods, f'{str(rule)}'))

    return urls


def get_app_test_client():
    """Return a flask api test client."""
    controller = get_controller_mock()
    napp = Main(controller)
    controller.api_server.register_napp_endpoints(napp)
    app = controller.api_server.app.test_client()
    return app


def get_event_listeners():
    """Return the event listeners name.

    Returns:
        list: list with all events listeners registered.

    """
    controller = get_controller_mock()
    napp = Main(controller)
    return napp.listeners()
