from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import AsyncGenerator


@dataclass
class ScanConfig:
    target_ips: list[str]
    options: dict = field(default_factory=dict)


@dataclass
class ScanProgressEvent:
    scan_job_id: str
    progress: int          # 0-100
    phase: str
    message: str
    current_host: str | None = None


@dataclass
class ScanResult:
    assets: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


class AbstractScanner(ABC):
    """Base class for all scanner modules."""

    @abstractmethod
    async def validate_scope(self, config: ScanConfig) -> bool:
        """Validate the scan scope before starting. Returns True if valid."""
        ...

    @abstractmethod
    async def scan(
        self, config: ScanConfig
    ) -> AsyncGenerator[ScanProgressEvent, None]:
        """Execute the scan, yielding progress events as work proceeds."""
        ...

    @abstractmethod
    async def get_results(self) -> ScanResult:
        """Return the accumulated scan results after scan() completes."""
        ...
