"""Module responsible to handle schedules."""
import time
from sched import scheduler
from kytos.core.helpers import now
from kytos.core import log


class Schedule:
    """Schedule events."""

    def __init__(self):
        """Initialize the schedule structure."""
        self.scheduler = scheduler(time.time, time.sleep)

    def run_pending(self):
        """Verify schedule and execute pended events."""
        self.scheduler.run(False)
        time.sleep(1)

    def circuit_deploy(self, circuit):
        """Add a new circuit deploy event."""
        seconds = (circuit.creation_time - now()).total_seconds()

        if not circuit.is_enabled():
            log.debug(f'{circuit} is not enabled')
        if not circuit.is_active():
            log.debug(f'{circuit} is not active')
        if circuit.is_enabled() and not circuit.is_active():
            self.scheduler.enter(seconds, circuit.priority, circuit.deploy)
            log.debug(f'{circuit} scheduled to be activated.')
