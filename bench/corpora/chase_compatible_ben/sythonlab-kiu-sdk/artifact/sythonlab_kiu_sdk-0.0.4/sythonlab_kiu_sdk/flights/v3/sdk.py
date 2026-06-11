import json
import logging
import os
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, Callable
from uuid import uuid4

import requests
import xmltodict

from sythonlab_kiu_sdk.flights.dataclasses import FlightRequestMetadata
from sythonlab_kiu_sdk.flights.enums import KiuTarget, Currency, FlightResultKind, RequestMethod

logger = logging.getLogger(__name__)


class KiuFlightSDK:
    debug: bool = False
    url_base: str = "https://ssl00.kiusys.com/ws3/index.php"
    username: Optional[str] = None
    password: Optional[str] = None
    headers: Dict[str, Any] = {}
    api_version = "3.0"
    target: Optional[KiuTarget] = None
    terminal_id: Optional[str] = None
    agent_sine: Optional[str] = None
    iso_country: Optional[str] = None
    iso_currency: Currency = Currency.USD

    def build_headers(self, headers: Optional[Dict[str, Any]] = None):
        if not headers:
            headers = {}

        self.headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            **headers
        }

    def __init__(
            self,
            iso_country: Optional[str] = None,
            *,
            username: Optional[str] = None,
            password: Optional[str] = None,
            target: Optional[KiuTarget] = None,
            terminal_id: Optional[str] = None,
            agent_sine: Optional[str] = None,
            iso_currency: Optional[Currency] = Currency.USD,
            debug: Optional[bool] = False
    ):
        self.username = username or os.getenv("KIU_V3_USERNAME", None)
        self.password = password or os.getenv("KIU_V3_PASSWORD", None)
        self.target = target or KiuTarget(os.getenv("KIU_V3_TARGET", None))
        self.terminal_id = terminal_id or os.getenv("KIU_V3_TERMINAL_ID", None)
        self.agent_sine = agent_sine or os.getenv("KIU_V3_AGENT_SINE", None)
        self.iso_country = iso_country
        self.debug = debug if debug is not None else False
        if iso_currency:
            self.iso_currency = iso_currency

    def request(
            self,
            request_id: str,
            *,
            payload: Optional[Dict[str, Any]] = None,
            headers: Optional[Dict[str, Any]] = None,
            method: RequestMethod = RequestMethod.POST,
            response_as_json: bool = True,
            on_complete: Optional[Callable] = None,
            kind: Optional[FlightResultKind] = None,
            show_response: bool = False,
            timeout: Optional[int] = 100
    ):
        """Make an HTTP request to the specified URL with the given payload and headers."""

        if not payload:
            payload = {}

        self.build_headers(headers)

        as_xml = ""
        if payload:
            as_xml = xmltodict.unparse(payload)

        payload = f"user={self.username}&password={self.password}&request={as_xml}"

        start = datetime.now(timezone.utc)

        if self.debug:
            logger.debug("-" * 100)
            logger.debug("URL: %s", self.url_base)
            logger.debug("Start time: %s", start.strftime("%d/%m/%Y %H:%M:%S"))
            logger.debug("Headers: %s", headers)
            logger.debug("Payload: %s", payload)

        if method == RequestMethod.POST:
            response = requests.post(self.url_base, data=payload, headers=self.headers, timeout=timeout)
        else:
            raise ValueError("Unsupported request method")

        end = None

        if self.debug:
            end = datetime.now(timezone.utc)

            logger.debug("-" * 100)
            logger.debug("End time: %s", end.strftime("%d/%m/%Y %H:%M:%S"))
            logger.debug("Duration: %s", end - start)
            logger.debug("Response status: %s", response.status_code)

        status_code, data = response.status_code, response.text

        if response_as_json:
            data = json.dumps(xmltodict.parse(data))

        if show_response:
            logger.debug("Response data: %s", data)

        if on_complete:
            on_complete(metadata=FlightRequestMetadata(
                status=status_code,
                request_id=request_id,
                kind=kind or FlightResultKind.UNKNOWN,
                headers=headers,
                request=payload,
                method=method,
                url=self.url_base,
                response=data,
                start_time=start,
                end_time=end,
                duration=(end - start).total_seconds() if end else None,
            ))

        if isinstance(data, dict):
            errors = self.extract_errors(data)
        else:
            errors = self.extract_errors(json.loads(data))

        if errors:
            return 400, errors

        return status_code, data

    @staticmethod
    def extract_errors(data: Dict[str, Any]):
        return data.get("Root", {}).get("Error")

    def check_connection(
            self,
            on_complete: Optional[Callable] = None,
            show_response: bool = False,
            timeout: Optional[int] = 100
    ):
        data = {
            'KIU_AirAvailRQ': {
                '@EchoToken': '1',
                '@TimeStamp': datetime.now(),
                '@Target': self.target.value,
                '@Version': self.api_version,
                '@SequenceNmbr': '1',
                '@PrimaryLangID': 'en-us',
                '@DirectFlightsOnly': False,
                '@MaxResponses': 1,
                '@CombinedItineraries': False,
                'POS': {
                    'Source': {
                        '@AgentSine': self.agent_sine,
                        '@TerminalID': self.terminal_id,
                        '@ISOCountry': self.iso_country
                    }
                },
                'OriginDestinationInformation': [{
                    'DepartureDateTime': (datetime.today() + timedelta(days=10)).strftime("%Y-%m-%d"),
                    'OriginLocation': {
                        '@LocationCode': "KIN"
                    },
                    'DestinationLocation': {
                        '@LocationCode': "MIA"
                    }
                }],
                'TravelerInfoSummary': {
                    'AirTravelerAvail': {
                        'PassengerTypeQuantity': [
                            {'@Code': "ADT", '@Quantity': 1}
                        ]
                    }
                }
            }
        }

        return self.request(
            request_id=str(uuid4()),
            payload=data,
            on_complete=on_complete,
            show_response=show_response,
            timeout=timeout
        )
