# SPDX-License-Identifier: GPL-3.0-only
"""在独立临时目录运行 build-kpm 工作流中的实际 Bash 步骤。"""

from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


REPO = Path(__file__).resolve().parents[1]


class WorkflowStepTestCase(unittest.TestCase):
    step_name: str

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def run_step(self):
        workflow = (REPO / ".github/workflows/build-kpm.yml").read_text()
        step = workflow.split(f"      - name: {self.step_name}\n", 1)[1].split("\n      - name:", 1)[0]
        script = textwrap.dedent(step.split("        run: |\n", 1)[1])
        return subprocess.run(["bash", "-e", "-o", "pipefail", "-c", script], cwd=self.root,
                              capture_output=True, text=True)
