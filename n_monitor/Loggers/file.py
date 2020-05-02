# coding=utf-8
import json
import os
import shutil
import socket
import stat
import subprocess  # nosec
import sys
import tempfile
import time
from io import StringIO
from typing import Any, List, Optional, TextIO, cast

import arrow

from ..Monitors.monitor import Monitor
from ..util import format_datetime, short_hostname
from .logger import Logger, register


@register
class FileLogger(Logger):
    """Log monitor status to a file."""

    _type = "logfile"
    filename = ""
    only_failures = False
    buffered = True
    dateformat = None

    def __init__(self, config_options: dict = None) -> None:
        if config_options is None:
            config_options = {}
        super().__init__(config_options)
        self.filename = self.get_config_option(
            "filename", required=True, allow_empty=False
        )
        self.file_handle = open(self.filename, "a+")

        self.only_failures = self.get_config_option(
            "only_failures", required_type="bool", default=False
        )

        self.buffered = self.get_config_option(
            "buffered", required_type="bool", default=True
        )

        self.dateformat = cast(
            str,
            self.get_config_option(
                "dateformat",
                required_type="str",
                allowed_values=["timestamp", "iso8601"],
                default="timestamp",
            ),
        )

        self.file_handle.write(
            "{} simplemonitor starting\n".format(self._get_datestring())
        )
        if not self.buffered:
            self.file_handle.flush()

    def __del__(self) -> None:
        self.file_handle.close()

    def _get_datestring(self) -> str:
        if self.dateformat == "iso8601":
            return format_datetime(arrow.now(), self.tz)
        return str(int(time.time()))

    def save_result2(self, name: str, monitor: Monitor) -> None:
        if self.only_failures and monitor.virtual_fail_count() == 0:
            return

        try:
            if monitor.virtual_fail_count() > 0:
                self.file_handle.write(
                    "%s %s: failed since %s; VFC=%d (%s) (%0.3fs)"
                    % (
                        self._get_datestring(),
                        name,
                        format_datetime(monitor.first_failure_time(), self.tz),
                        monitor.virtual_fail_count(),
                        monitor.get_result(),
                        monitor.last_run_duration,
                    )
                )
            else:
                self.file_handle.write(
                    "%s %s: ok (%0.3fs)"
                    % (self._get_datestring(), name, monitor.last_run_duration)
                )
            self.file_handle.write("\n")

            if not self.buffered:
                self.file_handle.flush()
        except OSError:
            self.logger_logger.exception("Error writing to logfile %s", self.filename)

    def hup(self) -> None:
        """Close and reopen log file."""
        try:
            self.file_handle.close()
            self.file_handle = open(self.filename, "a+")
        except OSError:
            self.logger_logger.exception(
                "Couldn't reopen log file %s after HUP", self.filename
            )

    def describe(self) -> str:
        return "Writing log file to {0}".format(self.filename)


class MonitorResult(object):
    """Represent the current status of a Monitor."""

    def __init__(self) -> None:
        self.virtual_fail_count = 0
        self.result = None  # type: Optional[str]
        self.first_failure_time = None  # type: Optional[str]
        self.last_run_duration = None  # type: Optional[int]
        self.status = "Fail"
        self.dependencies = []  # type: List[str]

    def json_representation(self) -> dict:
        return self.__dict__


class MonitorJsonPayload(object):
    def __init__(self) -> None:
        self.generated = None  # type: Optional[str]
        self.monitors = {}  # type: dict

    def json_representation(self) -> dict:
        return self.__dict__


class PayloadEncoder(json.JSONEncoder):
    def default(self, o: Any) -> Any:
        if hasattr(o, "json_representation"):
            return o.json_representation()
        return json.JSONEncoder.default(self, o.__dict__)


@register
class JsonLogger(Logger):
    """Write monitor status to a JSON file."""

    _type = "json"
    filename = ""  # type: str
    supports_batch = True

    def __init__(self, config_options: dict = None) -> None:
        if config_options is None:
            config_options = {}
        super().__init__(config_options)
        self.filename = self.get_config_option(
            "filename", required=True, allow_empty=False
        )

    def save_result2(self, name: str, monitor: Monitor) -> None:
        if self.batch_data is None:
            self.batch_data = {}
        result = MonitorResult()
        result.first_failure_time = format_datetime(monitor.first_failure_time())
        result.virtual_fail_count = monitor.virtual_fail_count()
        result.last_run_duration = monitor.last_run_duration
        result.result = monitor.get_result()
        if hasattr(monitor, "was_skipped") and monitor.was_skipped:
            result.status = "Skipped"
        elif monitor.virtual_fail_count() <= 0:
            result.status = "OK"
        result.dependencies = monitor.dependencies

        self.batch_data[name] = result

    def process_batch(self) -> None:
        payload = MonitorJsonPayload()
        payload.generated = format_datetime(arrow.now())
        if self.batch_data is not None:
            payload.monitors = self.batch_data

            with open(self.filename, "w") as outfile:
                json.dump(
                    payload,
                    outfile,
                    indent=4,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    cls=PayloadEncoder,
                )
        self.batch_data = {}

    def describe(self) -> str:
        return "Writing JSON file to {0}".format(self.filename)
