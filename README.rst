============
dnsdb-python
============

A full-featured unofficial Python client and CLI for
`Farsight Security's DNSDB`_ passive DNS service.

Features
--------

- Easy to use Python class covers all DNSDB API endpoints and options
- Supports hosted and self-hosted instances of DNSDB
- Full CLI
- Python 2 and 3 support
- Parses multiple human date formats for time filtering

  - 7 days
  - 7d
  - 2019-05-20
  - 1 month
  - 1m


- Automatically converts UNIX epoch timestamps to ISO 8601 timestamps
- Normalize timestamp fields for sensor and zone file observations
- Sort by any field
- Multiple output formats

  - Text (DNS master file format)
  - CSV
  - JSON

CLI
---

::

    Usage: dnsdb [OPTIONS] COMMAND [ARGS]...

      An unofficial Farsight Security DNSDB client

    Options:
      --version  Show the version and exit.
      --verbose  Enable verbose logging.
      --help     Show this message and exit.

    Commands:
      forward  Forward DNS lookup.
      inverse  Inverse DNS lookup.
      quotas   Show the API quotas for your API key and exit.

::

    Usage: dnsdb forward [OPTIONS] OWNER_NAME

      Forward DNS lookup.

    Options:
      -t, --rrtype TEXT               Filter results by DNS resource record type.
                                      [default: ANY]
      -b, --bailiwick TEXT            Filter results by DNS bailiwick.
      --first-seen-before TEXT        Only show results first seen before this
                                      date.
      --first-seen-after TEXT         Only show results first seen after this
                                      date.
      --last-seen-before TEXT         Only show results last seen before this
                                      date.
      --last-seen-after TEXT          Only show results last seen after this date.
      -l, --limit INTEGER             Limit the number of results to this number.
      -s, --sort [count|first_seen|last_seen|rrname|rrtype|bailiwick|rdata|source]
                                      Sort JSON results by this field.
      -r, --reverse                   Reverse the sorting.
      -f, --format [text|json|csv]    Set the screen output format.  [default:
                                      text]
      -o, --output FILE               One or more output file paths that end in
                                      .csv, .json,  or .txt (suppresses screen
                                      output).
      --help                          Show this message and exit.


::

    Usage: dnsdb inverse [OPTIONS] [name|ip|raw] VALUE

      Inverse DNS lookup.

    Options:
      -t, --rrtype TEXT               Filter results by DNS resource record type.
                                      [default: ANY]
      --first-seen-before TEXT        Only show results first seen before this
                                      date.
      --first-seen-after TEXT         Only show results first seen after this
                                      date.
      --last-seen-before TEXT         Only show results last seen before this
                                      date.
      --last-seen-after TEXT          Only show results last seen after this date.
      -l, --limit INTEGER             Limit the number of results to this number.
      -s, --sort [count|first_seen|last_seen|rrname|rrtype|bailiwick|rdata|source]
                                      Sort JSON results by this field.
      -r, --reverse                   Reverse the sorting.
      -f, --format [text|json|csv]    Set the screen output format.  [default:
                                      text]
      -o, --output FILE               One or more output file paths that end in
                                      .csv, .json,  or .txt (suppresses screen
                                      output).
      --help                          Show this message and exit.


Installation
------------

To install the latest stable version, run

.. code-block:: bash

    sudo -H pip3 install -U dnsdb-python

To install the latest development version, run

.. code-block:: bash

    sudo -H pip3 install -U git+https://github.com/domainaware/dnsdb-python.git

Store your API key as an environment variable named ``DNSDB_KEY``.

If you are using a self-hosted instance of DNSDB, store the URL root as an
environment variable named ``DNSDB_ROOT``.

See also
--------
- `DNSDB Community Edition`_
- `DNSDB API reference`_

.. _Farsight Security's DNSDB: https://www.farsightsecurity.com/solutions/dnsdb/
.. _DNSDB Community Edition: https://www.farsightsecurity.com/dnsdb-community-edition/
.. _DNSDB API reference: https://api.dnsdb.info/