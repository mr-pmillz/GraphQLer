"""A timed-out CLI must not leave children writing to a deleted output directory."""

import os
import subprocess
import sys

import pytest

from tests.utils.process import run_process


@pytest.mark.skipif(os.name != "posix", reason="POSIX process-group regression")
def test_timeout_kills_descendants_and_retains_diagnostics(tmp_path):
    import fcntl

    lock = tmp_path / "worker.lock"
    child = (
        "import fcntl, signal, sys, time; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        "f = open(sys.argv[1], 'w'); fcntl.flock(f, fcntl.LOCK_EX); "
        "print('worker ready', flush=True); time.sleep(60)"
    )
    parent = "import subprocess, sys, time; subprocess.Popen([sys.executable, '-c', sys.argv[1], sys.argv[2]]); time.sleep(60)"
    with pytest.raises(subprocess.TimeoutExpired) as error:
        run_process([sys.executable, "-c", parent, child, str(lock)], timeout=2)
    assert error.value.stdout is not None and b"worker ready" in error.value.stdout
    # A live orphan still holds this lock, even if its immediate parent has exited.
    with lock.open() as stream:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)


def test_completed_process_preserves_output_and_exit_code():
    result = run_process([sys.executable, "-c", "import sys; print('out'); print('err', file=sys.stderr); sys.exit(3)"], timeout=5)
    assert (result.returncode, result.stdout, result.stderr) == (3, "out\n", "err\n")
