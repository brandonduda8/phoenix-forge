"""Shared test helper: re-root tools.py at a throwaway temp workspace.

tools.py computes WORKSPACE/GENESIS/... from $HOME at import time. Tests
must never touch the real ~/workspace, so each test points those module
globals at a fresh temp directory and restores them afterwards. The gate
code itself is not modified or mocked.
"""
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
if REPO not in sys.path:
    sys.path.insert(0, REPO)

import tools as T  # noqa: E402

_ROOT_KEYS = ("WORKSPACE", "GENESIS", "TOOLS_DIR", "RUNS_DIR", "PLANS_FILE",
              "CRON_REGISTRY")


class SandboxTestCase(unittest.TestCase):
    def setUp(self):
        self._saved = {k: getattr(T, k) for k in _ROOT_KEYS}
        self.base = os.path.realpath(tempfile.mkdtemp(prefix="phx-test-"))
        self.ws = os.path.join(self.base, "workspace")
        self.outside = os.path.join(self.base, "outside")
        os.makedirs(self.ws)
        os.makedirs(self.outside)
        T.WORKSPACE = self.ws
        T.GENESIS = os.path.join(self.ws, "genesis-os")
        T.TOOLS_DIR = os.path.join(T.GENESIS, "tools")
        T.RUNS_DIR = os.path.join(T.GENESIS, "state", "phoenix_runs")
        T.PLANS_FILE = os.path.join(T.GENESIS, "state", "phoenix_plans.json")
        T.CRON_REGISTRY = os.path.join(T.GENESIS, "state", "phoenix_cron.json")
        self.run_dir = os.path.join(T.RUNS_DIR, "test-run")
        self.approvals = os.path.join(self.run_dir, "approvals")
        os.makedirs(self.approvals)
        self.ctx = {"run_id": "test-run", "run_dir": self.run_dir,
                    "approvals_dir": self.approvals}

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(T, k, v)
        shutil.rmtree(self.base, ignore_errors=True)

    def approve(self, gate):
        open(os.path.join(self.approvals, gate + ".approved"), "w").close()


class NoSubprocess:
    """Context manager: fail the test if anything tries to spawn a process."""

    def __enter__(self):
        import subprocess
        self._sp = subprocess
        self._run, self._popen = subprocess.run, subprocess.Popen

        def boom(*a, **k):
            raise AssertionError("subprocess was spawned: %r" % (a[:1],))
        subprocess.run = boom
        subprocess.Popen = boom
        return self

    def __exit__(self, *exc):
        self._sp.run, self._sp.Popen = self._run, self._popen
        return False
