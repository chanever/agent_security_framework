from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from sythonlab_kiu_sdk.flights.enums import RequestMethod, FlightResultKind


@dataclass
class FlightRequestMetadata:
    """Dataclass for flight request metadata."""

    status: int
    request_id: str
    method: RequestMethod
    url: str
    kind: FlightResultKind
    headers: Any
    request: Any
    response: Any
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration: Optional[float] = None
