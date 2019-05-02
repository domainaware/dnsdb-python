#!/usr/bin/enc/python
# -*- coding: utf-8 -*-

"""An unofficial Farsight Security DNSDB client"""

from __future__ import print_function, unicode_literals

import os
import logging
import json
from datetime import datetime

import dateparser
import click
from dateutil import tz
from requests import session

"""Copyright 2019 Sean Whalen

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License."""

__version__ = "1.0.0"


def _epoch_to_datetime(epoch_seconds):
    """
    Converts a UTC UNIX epoch timestamp to a Python DateTime object

    Args:
        epoch_seconds: A UNIX epoch value

    Returns:
        DateTime: A Python DateTime representation of the epoch value

    """
    if type(epoch_seconds) == datetime:
        return epoch_seconds
    else:
        return datetime.fromtimestamp(int(epoch_seconds), tz=tz.tzutc())


def _timestamp_to_iso8601(dt):
    """
    Converts a datetime object or epoch timestamp to an ISO 8601 string

    Args:
        dt (datetime): The datetime to convert
        dt (int): epoch timestamp

    Returns:

    str: a timestamp formatted ``YYYY-MM-DD HH:MM:SS``
    """

    if type(dt) == int:
        dt = _epoch_to_datetime(dt)

    return dt.isoformat()


def _datetime_to_timestamp(dt):
    """
    Converts a Python datetime object to a UNIX timestamp
    Args:
        dt (datetime): A python datetime object

    Returns:
        int: A UNIX timestamp
    """
    return int((dt - datetime(1970, 1, 1)).total_seconds())


class DNSDBAPIError(RuntimeError):
    """
    Raised when an error is returned by DNSDB
    """
    pass


class BadRequest(DNSDBAPIError):
    """
    Raised then a request is improperly formatted
    """


class UnauthorizedAPIKey(DNSDBAPIError):
    """
    Raised when the API key is not authorized
    (usually indicates the block quota is expired)
    """
    pass


class InvalidAPIKey(DNSDBAPIError):
    """
    Raised when the API key is invalid, or the client IP address is not
    authorized for the account
    """


class _NoRecordsFound(DNSDBAPIError):
    """
    Raised when no records are found for the given lookup
    """


class QuotaExceeded(DNSDBAPIError):
    """
    Raised when the API quota limit has been exceeded

    For time-based quotas: The API key daily quota limit is exceeded. The
    quota will automatically replenish, usually at the start of the next day.

    For block-based quotas: The block quota is exhausted. You may need to
    purchase a larger quota.

    For burst rate secondary quotas: There were too many queries within the
    burst window. The window will automatically reopen at its end.
    """
    pass


class ServerSideError(DNSDBAPIError):
    """
    Raised when a server side error occurs
    """
    pass


class TooManyConnections(DNSDBAPIError):
    """
    Raised when the limit of number of concurrent connections is exceeded
    """
    pass


def _load_json(dnsdb_json_string, sort_by=None, reverse=False):
    """
    Converts the lines of separate provided by DNSDB to a Python list

    Args:
        dnsdb_json_string (str): JSON output from DNSDBAPI
        sort_by: An optional field to sort by
        reverse (bool): Reverse the sorting

    Returns:
        list: A Python list of result of result dictionaries, with
        human-readable ISO 8601 timestamps
    """
    results = []
    for line in dnsdb_json_string.split("\n"):
        if len(line) > 1:
            result = json.loads(line, encoding="uft-8")
            if "zone_time_first" in result:
                result["time_first"] = result["zone_time_first"]
                result["time_last"] = result["zone_time_last"]
                del result["zone_time_first"]
                del result["zone_time_last"]
                result["source"] = "zone"
            else:
                result["source"] = "sensor"
            results.append(result)

    if sort_by is not None:
        try:
            results = list(sorted(
                results,
                key=lambda x: x[sort_by], reverse=reverse)).copy()
        except KeyError:
            raise KeyError("Unable to sort by {0}. "
                           "Field does not exist".format(sort_by))
    for result in results:
        if "time_first" in result:
            result["time_first"] = _timestamp_to_iso8601(
                result["time_first"])
        if "time_last" in result:
            result["time_last"] = _timestamp_to_iso8601(
                result["time_last"])

    return results


class DNSDBAPI(object):
    """
    A Python interface to the Farsight Security DNSDB API
    ..
    """

    def __init__(self, api_key=None, client_name=None, client_version=None,
                 url_root="https://api.dnsdb.info"):
        """
        Configures the API client

        Args:
            api_key (str): WhoisXMLAPI API key; overridden by the
            ``WHOIS_KEY`` environment variable
            client_name (str): The client's name
            client_version (str): The client's version
            url_root (str): The root URL of the DNSDB API
        """
        if "DNSDB_KEY" in os.environ:
            api_key = os.environ["DNSDB_KEY"]
        if "DNSDB_ROOT" in os.environ:
            url_root = os.environ["DNSDB_ROOT"]
        if api_key is None:
            raise InvalidAPIKey(
                " An API key must provided as the api_key parameter, or the "
                "DNSDB_KEY environment variable.")
        if client_name is None or client_version is None:
            self.client_name = "dnsdb-python"
            self.client_version = __version__
        else:
            self.client_name = client_name,
            self.client_version = client_version

        user_agent = "{0}/{1}".format(self.client_name, self.client_version)
        default_headers = {"User-Agent": user_agent, "X-API-Key": api_key}
        self._root = url_root
        self._api_key = api_key
        self._session = session()
        self._session.headers.update(default_headers)

    def _get(self, endpoint, params=None, _json=False,
             sort_by=None, reverse=False):
        default_params = dict(swclient=self.client_name,
                              version=self.client_version)
        _params = default_params.copy()
        if params:
            _params.update(params)
        endpoint = "{0}/{1}".format(self._root, endpoint.strip("/"))
        headers = self._session.headers
        if _json is False and sort_by is not None:
            raise ValueError("Sorting can only be used with JSON")
        if _json:
            headers.update({"Accept": "application/json"})
        response = self._session.get(endpoint, headers=headers, params=_params)
        if response.status_code == 200:
            if _json:
                return _load_json(response.text, sort_by=sort_by,
                                  reverse=reverse)
            else:
                return response.text
        if response.status_code == 400:
            raise BadRequest("The request is improperly formatted")
        elif response.status_code == 401:
            error_msg = "the API key is not authorized " \
                        "(usually indicates the block quota is expired)"
            raise UnauthorizedAPIKey(error_msg)
        elif response.status_code == 403:
            error_msg = "The API key is invalid, or the client IP " \
                        "address is not authorized for the account"
            raise InvalidAPIKey(error_msg)
        elif response.status_code == 404:
            raise _NoRecordsFound("No records found for the given lookup")
        elif response.status_code == 429:
            raise QuotaExceeded("API quota exceeded")
        elif response.status_code == 500:
            raise ServerSideError("Error processing the request")
        elif response.status_code == 503:
            raise TooManyConnections("Too many concurrent connections")
        else:
            error_msg = "Unexpected status code: " \
                        "{0}".format(response.status_code)
            raise DNSDBAPIError(error_msg)

    def get_quotas(self):
        quotas = self._get("/lookup/rate_limit")
        quotas = json.loads(quotas)["rate"]
        if "limit" in quotas:
            if quotas["limit"] == "unlimited":
                quotas["limit"] = None
        if "reset" in quotas:
            if quotas["reset"] == "n/a":
                del quotas["reset"]
            else:
                quotas["reset"] = _timestamp_to_iso8601(quotas["reset"])
        if "expires" in quotas:
            if quotas["expires"] == "n/a":
                del quotas["expires"]
            else:
                quotas["expires"] = _timestamp_to_iso8601(quotas["expires"])
        if "remaining" in quotas:
            if quotas["remaining"] == "n/a":
                del quotas["remaining"]

        return quotas

    def forward_lookup(self, owner_name, rrtype="ANY", bailiwick=None,
                       first_seen_before=None, first_seen_after=None,
                       last_seen_before=None, last_seen_after=None,
                       limit=None, sort_by=None, reverse=False,
                       return_text=False):
        """
        Performs a forward DNS lookup

        Args:
            owner_name (str): The DNS Owner Name
            rrtype (str): The DNS Resource Record type
            bailiwick (str): The DNS bailiwick
            first_seen_before (str): Filter results first seen before this date
            first_seen_after (str): Filter results first seen after this date
            last_seen_before (str): Filter results last seen before this date
            last_seen_after (str): Filter results first seen before after date
            limit (int): The maximum number of results to return
            sort_by: An optional field to sort by
            reverse (bool): Reverse the sorting
            return_text (bool): Return results in DNS master file format

        Returns:
            Results as a Python list, or as text in DNS master file format
            if ``return_text`` is ``True``
        """
        if rrtype is not None:
            rrtype = rrtype.upper()
        params = dict()
        _json = return_text is False
        if limit is not None:
            params["limit"] = limit
        if bailiwick is not None and rrtype is None:
            raise ValueError("rrtype must be specified when using bailiwick")
        endpoint = "/lookup/rrset/name/{0}".format(owner_name)
        if rrtype is not None:
            endpoint += "/{0}".format(rrtype)
        if bailiwick is not None:
            endpoint += "/{0}".format(bailiwick)
        if first_seen_before is not None:
            first_seen_before = _datetime_to_timestamp(
                dateparser.parse(first_seen_before))
            params["time_first_before"] = first_seen_before
        if first_seen_after is not None:
            first_seen_after = _datetime_to_timestamp(
                dateparser.parse(first_seen_after))
            params["time_first_after"] = first_seen_after
        if last_seen_before is not None:
            last_seen_before = _datetime_to_timestamp(
                dateparser.parse(last_seen_before))
            params["time_last_before"] = last_seen_before
        if last_seen_after is not None:
            last_seen_after = _datetime_to_timestamp(
                dateparser.parse(last_seen_after))
            params["time_last_after"] = last_seen_after
        try:
            return self._get(endpoint, params=params, _json=_json,
                             sort_by=sort_by, reverse=reverse)
        except _NoRecordsFound:
            if return_text:
                return ""
            else:
                return []

    def inverse_lookup(self, _type, value, rrtype=None,
                       first_seen_before=None, first_seen_after=None,
                       last_seen_before=None, last_seen_after=None,
                       limit=None, sort_by=None, reverse=None,
                       return_text=False):
        """
        Performs a inverse DNS lookup

        Args:
            _type (str): ``name``, ``ip``, or ``raw``
            value (str): The rdata value to search for
            rrtype (str): The DNS Resource Record type
            first_seen_before (str): Filter results first seen before this date
            first_seen_after (str): Filter results first seen after this date
            last_seen_before (str): Filter results last seen before this date
            last_seen_after (str): Filter results first seen before after date
            limit (int): The maximum number of results to return
            sort_by: An optional field to sort by
            reverse (bool): Reverse the sorting
            return_text (bool): Return results in DNS master file format

        Returns:
            Results as a Python list, or as text in DNS master file format
            if ``return_text`` is ``True``
        """
        if rrtype is not None:
            rrtype = rrtype.upper()
        params = dict()
        _json = return_text is False
        if limit is not None:
            params["limit"] = limit
        _type = _type.lower()
        if _type not in ["name", "ip", "raw"]:
            raise ValueError("_type must be name ip or raw")
        endpoint = "/lookup/rdata/{0}/{1}".format(_type, value)
        if rrtype is not None:
            endpoint += "/{0}".format(rrtype)
        if first_seen_before is not None:
            first_seen_before = _datetime_to_timestamp(
                dateparser.parse(first_seen_before))
            params["time_first_before"] = first_seen_before
        if first_seen_after is not None:
            first_seen_after = _datetime_to_timestamp(
                dateparser.parse(first_seen_after))
            params["time_first_after"] = first_seen_after
        if last_seen_before is not None:
            last_seen_before = _datetime_to_timestamp(
                dateparser.parse(last_seen_before))
            params["time_last_before"] = last_seen_before
        if last_seen_after is not None:
            last_seen_after = _datetime_to_timestamp(
                dateparser.parse(last_seen_after))
            params["time_last_after"] = last_seen_after

        try:
            return self._get(endpoint, params=params, _json=_json,
                             sort_by=sort_by, reverse=reverse)
        except _NoRecordsFound:
            if return_text:
                return ""
            else:
                return []


class _CLIConfig(object):
    def __init__(self, verbose=False):
        if verbose:
            logging.basicConfig(level=logging.INFO,
                                format="%(levelname)s: %(message)s")
        else:
            logging.basicConfig(level=logging.WARNING,
                                format="%(levelname)s: %(message)s")
            try:
                self.client = DNSDBAPI()
            except InvalidAPIKey:
                logging.error("DNSDB_KEY environment variable missing or "
                              "invalid.")
                exit(-1)


@click.group()
@click.version_option(version=__version__)
@click.option("--verbose", is_flag=True, help="Enable verbose logging.")
@click.pass_context
def _main(ctx, verbose=False):
    """An unofficial Farsight Security DNSDB client"""
    ctx.obj = _CLIConfig(verbose=verbose)


@_main.command("quotas")
@click.pass_context
def _get_quotas(ctx):
    """Show the API quotas for your API key and exit."""
    print(json.dumps(ctx.obj.client.get_quotas(), indent=2))


@_main.command("forward")
@click.argument("owner_name")
@click.option("-t", "--rrtype", help="Filter results by DNS resource record "
                                     "type.",
              default="ANY", show_default=True)
@click.option("-b", "--bailiwick", help="Filter results by DNS bailiwick.")
@click.option("--first-seen-before",
              help="Only show results first seen before this date.")
@click.option("--first-seen-after",
              help="Only show results first seen after this date.")
@click.option("--first-seen-before",
              help="Only show results first seen before this date.")
@click.option("--first-seen-after",
              help="Only show results first seen after this date.")
@click.option("--last-seen-before",
              help="Only show results last seen before this date.")
@click.option("--last-seen-after",
              help="Only show results last seen after this date.")
@click.option("-l", "--limit", type=int,
              help="Limit the number of results to this number.")
@click.option("-j", "--json", "_json", is_flag=True,
              help="Output in JSON format.")
@click.option("-s", "--sort", "sort_by",
              help="Sort JSON results by this field.",
              type=click.Choice(["count", "time_first", "time_last",
                                 "rrname", "rrtype", "bailiwick", "rdata",
                                 "source"])
              )
@click.option("-r", "--reverse", is_flag=True, help="Reverse the sorting.")
@click.pass_context
def _forward_lookup(ctx, owner_name, rrtype="ANY", bailiwick=None,
                    first_seen_before=None, first_seen_after=None,
                    last_seen_before=None, last_seen_after=None,
                    limit=None, _json=False, sort_by=None, reverse=False):
    """Forward DNS lookup."""
    try:
        results = ctx.obj.client.forward_lookup(
            owner_name, rrtype=rrtype,
            bailiwick=bailiwick,
            first_seen_before=first_seen_before,
            first_seen_after=first_seen_after,
            last_seen_before=last_seen_before,
            last_seen_after=last_seen_after,
            limit=limit,
            return_text=_json is False,
            sort_by=sort_by,
            reverse=reverse
        )
        if _json:
            print(json.dumps(results, indent=2, ensure_ascii=False))
        else:
            print(results)
    except Exception as e:
        logging.error(e.__str__())
        exit(-1)


@_main.command("inverse")
@click.argument("query_type", type=click.Choice(["name", "ip", "raw"]))
@click.argument("value")
@click.option("-t", "--rrtype", help="Filter results by DNS resource record "
                                     "type.",
              default="ANY", show_default=True)
@click.option("--first-seen-before",
              help="Only show results first seen before this date.")
@click.option("--first-seen-after",
              help="Only show results first seen after this date.")
@click.option("--first-seen-before",
              help="Only show results first seen before this date.")
@click.option("--first-seen-after",
              help="Only show results first seen after this date.")
@click.option("--last-seen-before",
              help="Only show results last seen before this date.")
@click.option("--last-seen-after",
              help="Only show results last seen after this date.")
@click.option("-l", "--limit", type=int,
              help="Limit the number of results to this number.")
@click.option("-j", "--json", "_json", is_flag=True,
              help="Output in JSON format.")
@click.option("-s", "--sort", "sort_by",
              help="Sort JSON results by this field.",
              type=click.Choice(["count", "time_first", "time_last",
                                 "rrname", "rrtype", "bailiwick", "rdata",
                                 "source"])
              )
@click.option("-r", "--reverse", is_flag=True, help="Reverse the sorting.")
@click.pass_context
def _inverse_lookup(ctx, query_type, value, rrtype="ANY",
                    first_seen_before=None, first_seen_after=None,
                    last_seen_before=None, last_seen_after=None,
                    limit=None, _json=False, sort_by=None, reverse=False):
    """Inverse DNS lookup."""
    try:
        results = ctx.obj.client.inverse_lookup(
            query_type, value, rrtype=rrtype,
            first_seen_before=first_seen_before,
            first_seen_after=first_seen_after,
            last_seen_before=last_seen_before,
            last_seen_after=last_seen_after,
            limit=limit,
            return_text=_json is False,
            sort_by=sort_by,
            reverse=reverse
        )
        if _json:
            print(json.dumps(results, indent=2, ensure_ascii=False))
        else:
            print(results)
    except Exception as e:
        logging.error(e.__str__())
        exit(-1)


if __name__ == "__main__":
    _main()
