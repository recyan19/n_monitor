import os
import re
import shlex
import subprocess  # nosec
import time
from typing import Optional, Tuple, cast

from .monitor import Monitor, register

try:
    import psutil
except ImportError:
    psutil = None


try:
    import win32api

    win32_available = True
except ImportError:
    win32_available = False


def _size_string_to_bytes(s: str) -> Optional[int]:
    if s is None:
        return None
    if s.endswith("G"):
        gigs = int(s[:-1])
        _bytes = gigs * (1024 ** 3)
    elif s.endswith("M"):
        megs = int(s[:-1])
        _bytes = megs * (1024 ** 2)
    elif s.endswith("K"):
        kilos = int(s[:-1])
        _bytes = kilos * 1024
    else:
        return int(s)
    return _bytes


def _bytes_to_size_string(b: int) -> str:
    """Convert a number in bytes to a sensible unit."""

    kb = 1024
    mb = kb * 1024
    gb = mb * 1024
    tb = gb * 1024

    if b > tb:
        return "%0.2fTiB" % (b / float(tb))
    if b > gb:
        return "%0.2fGiB" % (b / float(gb))
    if b > mb:
        return "%0.2fMiB" % (b / float(mb))
    if b > kb:
        return "%0.2fKiB" % (b / float(kb))
    return str(b)


@register
class MonitorDiskSpace(Monitor):
    """Make sure we have enough disk space."""

    _type = "diskspace"

    def __init__(self, name: str, config_options: dict) -> None:
        super().__init__(name, config_options)
        if self.is_windows(allow_cygwin=False):
            self.use_statvfs = False
            if not win32_available:
                raise RuntimeError(
                    "win32api is not available, but is needed for DiskSpace monitor."
                )
        else:
            self.use_statvfs = True
        self.partition = self.get_config_option("partition", required=True)
        self.limit = _size_string_to_bytes(
            self.get_config_option("limit", required=True)
        )

    def run_test(self) -> bool:
        try:
            if self.use_statvfs:
                result = os.statvfs(self.partition)
                space = result.f_bavail * result.f_frsize
                percent = float(result.f_bavail) / float(result.f_blocks) * 100
            else:
                win_result = win32api.GetDiskFreeSpaceEx(self.partition)
                space = win_result[2]
                percent = float(win_result[2]) / float(win_result[1]) * 100
        except Exception as e:
            return self.record_fail("Couldn't get free disk space: %s" % e)

        if self.limit and space <= self.limit:
            return self.record_fail(
                "%s free (%d%%)" % (_bytes_to_size_string(space), percent)
            )
        return self.record_success(
            "%s free (%d%%)" % (_bytes_to_size_string(space), percent)
        )

    def describe(self) -> str:
        """Explains what we do."""
        if self.limit is None:
            limit = "none"
        else:
            limit = _bytes_to_size_string(self.limit)

        return "Checking for at least %s free space on %s" % (limit, self.partition)

    def get_params(self) -> Tuple:
        return (self.limit, self.partition)


@register
class MonitorPortAudit(Monitor):
    """Check a host doesn't have outstanding security issues."""

    _type = "portaudit"
    regexp = re.compile(r"(\d+) problem\(s\) in your installed packages found")

    def __init__(self, name: str, config_options: dict) -> None:
        super().__init__(name, config_options)
        self.path = self.get_config_option("path", default="")

    def describe(self) -> str:
        return "Checking for insecure ports."

    def get_params(self) -> Tuple:
        return (self.path,)

    def run_test(self) -> bool:
        try:
            # -X 1 tells portaudit to re-download db if one day out of date
            if self.path == "":
                self.path = "/usr/local/sbin/portaudit"
            try:
                # nosec
                _output = subprocess.check_output([self.path, "-a", "-X", "1"])  # nosec
                output = _output.decode("utf-8")
            except subprocess.CalledProcessError as e:
                output = e.output
            except OSError as e:
                return self.record_fail("Error running %s: %s" % (self.path, e))
            except Exception as e:
                return self.record_fail("Error running portaudit: %s" % e)

            for line in output.splitlines():
                matches = self.regexp.match(line)
                if matches:
                    count = int(matches.group(1))
                    # sanity check
                    if count == 0:
                        return self.record_success()
                    if count == 1:
                        return self.record_fail("1 problem")
                    return self.record_fail("%d problems" % count)
            return self.record_success()
        except Exception as e:
            return self.record_fail("Could not run portaudit: %s" % e)


@register
class MonitorLoadAvg(Monitor):
    """Check a host's load average isn't too high."""

    _type = "loadavg"

    def __init__(self, name: str, config_options: dict) -> None:
        super().__init__(name, config_options)
        if self.is_windows(allow_cygwin=False):
            raise RuntimeError("loadavg monitor does not support Windows")
        # which time field we're looking at: 0 = 1min, 1 = 5min, 2=15min
        self.which = self.get_config_option(
            "which", required_type="int", default=1, minimum=0, maximum=2
        )
        self.max = self.get_config_option(
            "max", required_type="float", default=1.00, minimum=0
        )

    def describe(self) -> str:
        if self.which == 0:
            return "Checking 1min loadavg is <= %0.2f" % self.max
        elif self.which == 1:
            return "Checking 5min loadavg is <= %0.2f" % self.max
        else:
            return "Checking 15min loadavg is <= %0.2f" % self.max

    def run_test(self) -> bool:
        try:
            loadavg = os.getloadavg()
        except Exception as e:
            return self.record_fail("Exception getting loadavg: %s" % e)

        if loadavg[self.which] > self.max:
            return self.record_fail("%0.2f" % loadavg[self.which])
        return self.record_success("%0.2f" % loadavg[self.which])

    def get_params(self) -> Tuple:
        return (self.which, self.max)


@register
class MonitorMemory(Monitor):
    """Check for available memory."""

    _type = "memory"

    def __init__(self, name: str, config_options: dict) -> None:
        super().__init__(name, config_options)
        if psutil is None:
            self.monitor_logger.critical("psutil is not installed.")
            self.monitor_logger.critical("Try: pip install -r requirements.txt")
        self.percent_free = cast(
            int,
            self.get_config_option("percent_free", required_type="int", required=True),
        )

    def run_test(self) -> bool:
        if psutil is None:
            return self.record_fail("psutil is not installed")
        stats = psutil.virtual_memory()
        percent = int(stats.available / stats.total * 100)
        message = "{}% free".format(percent)
        if percent < self.percent_free:
            return self.record_fail(message)
        else:
            return self.record_success(message)

    def get_params(self) -> Tuple:
        return (self.percent_free,)

    def describe(self) -> str:
        return "Checking for at least {}% free memory".format(self.percent_free)


@register
class MonitorSwap(Monitor):
    """Check for available swap."""

    _type = "swap"

    def __init__(self, name: str, config_options: dict) -> None:
        super().__init__(name, config_options)
        if psutil is None:
            self.monitor_logger.critical("psutil is not installed.")
            self.monitor_logger.critical("Try: pip install -r requirements.txt")
        self.percent_free = cast(
            int,
            self.get_config_option("percent_free", required_type="int", required=True),
        )

    def run_test(self) -> bool:
        if psutil is None:
            return self.record_fail("psutil is not installed")
        stats = psutil.swap_memory()
        percent = 100 - stats.percent
        message = "{}% free".format(percent)
        if percent < self.percent_free:
            return self.record_fail(message)
        else:
            return self.record_success(message)

    def get_params(self) -> Tuple:
        return (self.percent_free,)

    def describe(self) -> str:
        return "Checking for at least {}% free swap".format(self.percent_free)
