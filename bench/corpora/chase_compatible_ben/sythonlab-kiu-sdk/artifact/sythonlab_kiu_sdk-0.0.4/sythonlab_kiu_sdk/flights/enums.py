from enum import Enum


class KiuTarget(Enum):
    TESTING = "Testing"
    PRODUCTION = "Production"


class Currency(Enum):
    """Represents different currency codes."""

    USD = "USD"
    JMD = "JMD"


class FlightResultKind(Enum):
    """Enum for the kind of flight result."""

    UNKNOWN = "UNKNOWN"
    LOGIN = "LOGIN"
    FLIGHT_SEARCH = "FLIGHT_SEARCH"


class RequestMethod(Enum):
    """Represents HTTP request methods."""

    POST = "POST"
