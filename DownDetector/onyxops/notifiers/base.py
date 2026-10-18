from abc import ABC, abstractmethod
from typing import Optional
from onyxops.core.models import DeepScanReport, UptimeResult

class BaseNotifier(ABC):
    """Abstract base class for OnyxOps alert notification channels."""

    @abstractmethod
    async def send_down_alert(self, report: DeepScanReport) -> bool:
        """Dispatched when a site goes down or critical failure is detected."""
        pass

    @abstractmethod
    async def send_recovery_alert(self, result: UptimeResult, site_name: str) -> bool:
        """Dispatched when a previously down site recovers."""
        pass

    @abstractmethod
    async def send_security_alert(self, report: DeepScanReport) -> bool:
        """Dispatched when critical security flaws or malware signatures are found."""
        pass
