"""Subprocess helpers that do not leave scan workers running after a test timeout."""

import os
import signal
import subprocess


def run_process(command: list[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
    """Capture a command, killing its process tree before returning from a timeout."""
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                          start_new_session=os.name == "posix") as process:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except BaseException as exc:
            if os.name == "posix":
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(process.pid)], capture_output=True, check=False)
                if process.poll() is None:
                    process.kill()
            stdout, stderr = process.communicate()
            if isinstance(exc, subprocess.TimeoutExpired):
                raise subprocess.TimeoutExpired(command, timeout, output=stdout.encode(), stderr=stderr.encode()) from exc
            raise
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
