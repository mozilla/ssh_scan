# ssh_scan API documentation

**API Version:** 1.0
**Status:** not ready

This document explains the ssh_scan Web API, intended to be used in the Web API for ssh_scan.

## Protocol Calls

### scan

**API Call:** `scan` <br>
**API Method:** `POST`

Scans a target, with an optional port (default 22). Equivalent to `ssh_scan -t host -p port`.
Parameters:
* `target` (required), which can be a hostname or an IP address

POST Parameters:
* `port` on which to scan (optional)

Examples:
* `/api/v1/scan?host=www.mozilla.org`
* `/api/v1/scan?host=115.223.33.44`
  * `port=9999` (POST data)

### __version__

**API Call:** `__version__` <br>
**API Method:** `GET`

Returns version details for ssh_scan being used and API.

Example:
* `/api/v1/__version__`
  * Returns `{ "ssh_scan_version": "0.0.1", "api_version": "1" }`
