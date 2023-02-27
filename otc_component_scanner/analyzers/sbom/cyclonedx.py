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
import subprocess

from otc_component_scanner.analyzers import Analyzer


class CycloneDXPySbom(Analyzer):
    name = "CycloneDX-py"
    match_globs = [
        "requirements.txt",
    ]

    @classmethod
    def is_applicable(cls, path):
        logging.debug("Checking %s path", path.resolve())
        for match_glob in cls.match_globs:
            if len(list(path.glob(match_glob))) > 0:
                return True
        return False

    @classmethod
    def execute(cls, path):
        results = dict()
        for match_glob in cls.match_globs:
            for req in path.glob(match_glob):
                res = subprocess.run(
                    args=[
                        "cyclonedx-py",
                        "-r",
                        "-i",
                        f"{req.resolve()}",
                        "-o",
                        "-",
                    ],
                    cwd=path,
                    check=False,
                    capture_output=True,
                )
                logging.debug("stdout= !!%s!!", res.stdout)
                # results[req.relative_to(path).as_posix()] = res.stdout
                results = res.stdout
        ver = subprocess.run(
            args=[
                "python",
                "-c",
                "from pbr import packaging; print(packaging.get_version(''))"
                "--version",
            ],
            cwd=path,
            check=False,
            capture_output=True,
        )
        print("Verision=%s" % ver.stdout)
        return {"sbom": results, "version": ver.stdout.decode()}
