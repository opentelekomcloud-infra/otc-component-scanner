# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import pathlib
import subprocess

from otc_component_scanner.analyzers import Analyzer


class SyftSbom(Analyzer):
    name = "Syft"
    skip_globs = [
        "tox.ini",
        "**/*requiurement.txt",
    ]

    @classmethod
    def is_applicable(cls, path):
        for skip_glob in cls.skip_globs:
            if len(list(path.glob(skip_glob))) > 0:
                logging.debug(
                    "Path %s contain one or more of skip_glob entries",
                    path.resolve(),
                )
                return False
        return True

    @classmethod
    def execute(cls, path=None):
        res = subprocess.run(
            args=[
                "syft",
                "packages",
                path.resolve() if isinstance(path, pathlib.Path) else path,
                # "--name", canonical_name,
                "-o",
                "cyclonedx-xml",
            ],
            check=False,
            capture_output=True,
        )
        return {"sbom": res.stdout}
