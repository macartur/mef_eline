"""Module to test the schedule.py file."""
from unittest import TestCase
from unittest.mock import MagicMock, PropertyMock, patch
import json
from datetime import datetime
from apscheduler.triggers.cron import CronTrigger
from pytz import utc

from tests.helper import (get_app_test_client, get_event_listeners,
                          get_controller_mock, get_napp_urls)

# import NAppMain
from napps.kytos.mef_eline.scheduler import CircuitSchedule, Scheduler
from napps.kytos.mef_eline.models import EVC


class TestCircuitSchedule(TestCase):
    """Tests to verify circuit_schedule class."""

    def test_create_circuit_schedule_always_create_different_id(self):
        """Test method id with different values."""
        self.assertNotEqual(CircuitSchedule().id, CircuitSchedule().id)

    def test_create_circuit_schedule_with_date(self):
        """Test create circuit schedule with date."""
        time_fmt = "%Y-%m-%dT%H:%M:%S"
        options = {
            "action": "create",
            "date": datetime.now().strftime(time_fmt)
        }
        circuit_schedule = CircuitSchedule(**options)
        self.assertEqual("create", circuit_schedule.action)
        self.assertEqual(options["date"], circuit_schedule.date)

    def test_create_circuit_schedule_with_interval(self):
        """Test create circuit schedule with interval."""
        options = {
            "action": "create",
            "interval":{
                "hours": 2
            }
        }
        circuit_schedule = CircuitSchedule(**options)
        self.assertEqual("create", circuit_schedule.action)
        self.assertEqual(options["interval"], circuit_schedule.interval)

    def test_create_circuit_schedule_with_frequency(self):
        """Test create circuit schedule with frequency."""
        options = {
            "action": "create",
            "frequency": "1 * * * *"
        }
        circuit_schedule = CircuitSchedule(**options)
        self.assertEqual("create", circuit_schedule.action)
        self.assertEqual(options["frequency"], circuit_schedule.frequency)

    def test_create_circuit_schedule_from_dict(self):
        """Test create circuit schedule from dict."""
        circuit_schedule_dict = {
            "id": 52342432,
            "action": "create",
            "frequency": "1 * * * *"
        }
        circuit_schedule = CircuitSchedule.from_dict(circuit_schedule_dict)
        self.assertEqual(circuit_schedule.id, circuit_schedule_dict["id"])
        self.assertEqual(circuit_schedule.action,
                         circuit_schedule_dict["action"])
        self.assertEqual(circuit_schedule.frequency,
                         circuit_schedule_dict["frequency"])

    def test_circuit_schedule_as_dict(self):
        """Test method as_dict from circuit_schedule."""
        options = {
            "id": 234243242,
            "action": "create",
            "frequency": "1 * * * *"
        }
        circuit_schedule_dict = CircuitSchedule(**options).as_dict()
        self.assertEqual(options, circuit_schedule_dict)


class TestScheduler(TestCase):

    def setUp(self):
        self.scheduler =  Scheduler()

    def tearDown(self):
        self.scheduler.shutdown()

    @patch('apscheduler.schedulers.background.BackgroundScheduler.add_job')
    @patch('napps.kytos.mef_eline.models.EVC._validate')
    def test_add_new_circuit_with_run_time(self, validate_mock,
                                       scheduler_add_job_mock):
        """Test if add new circuit with run_time."""
        scheduler_add_job_mock.return_value = True
        validate_mock.return_value = True
        time_fmt = "%Y-%m-%dT%H:%M:%S"
        date=datetime.now().strftime(time_fmt)
        circuit_scheduler = CircuitSchedule(action="remove", date=date)
        options = {"name": 'my evc1',
                   "uni_a": 'uni_a',
                   "uni_z": 'uni_z',
                   "circuit_scheduler": [circuit_scheduler]
                  }
        evc = EVC(**options)
        self.scheduler.add(evc)
        scheduler_add_job_mock.assert_called_once_with(evc.remove, 'date',
            end_date=None, id=circuit_scheduler.id,
            run_time=circuit_scheduler.date,
            start_date=evc.start_date)

    @patch('apscheduler.schedulers.background.BackgroundScheduler.add_job')
    @patch('napps.kytos.mef_eline.models.EVC._validate')
    def test_add_new_circuit_with_interval(self, validate_mock,
                                       scheduler_add_job_mock):
        """Test if add new circuit with interval."""
        scheduler_add_job_mock.return_value = True
        validate_mock.return_value = True
        interval = {
            'hours': 2,
            'minutes': 3
        }
        circuit_scheduler = CircuitSchedule(action="create", interval=interval)
        options = {"name": 'my evc1',
                   "uni_a": 'uni_a',
                   "uni_z": 'uni_z',
                   "circuit_scheduler": [circuit_scheduler]
                  }
        evc = EVC(**options)
        self.scheduler.add(evc)
        scheduler_add_job_mock.assert_called_once_with(evc.deploy, 'interval',
            end_date=None, id=circuit_scheduler.id, hours=2, minutes=3,
            start_date=evc.start_date)

    @patch('apscheduler.schedulers.background.BackgroundScheduler.add_job')
    @patch('napps.kytos.mef_eline.models.EVC._validate')
    def test_add_new_circuit_with_frequency(self, validate_mock,
                                       scheduler_add_job_mock):
        """Test if add new circuit with frequency."""
        scheduler_add_job_mock.return_value = True
        validate_mock.return_value = True
        frequency = "* * * * *"
        circuit_scheduler = CircuitSchedule(action="create",
                                            frequency=frequency)
        options = {"name": 'my evc1',
                   "uni_a": 'uni_a',
                   "uni_z": 'uni_z',
                   "circuit_scheduler": [circuit_scheduler]
                  }
        evc = EVC(**options)
        self.scheduler.add(evc)
        trigger = CronTrigger.from_crontab(circuit_scheduler.frequency,
                                           timezone=utc)
        scheduler_add_job_mock.assert_called_once_with(evc.deploy, trigger,
            end_date=None, id=circuit_scheduler.id,
            start_date=evc.start_date)
