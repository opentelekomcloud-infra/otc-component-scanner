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

import base64
import logging
import requests


class DependencytrackReporter:
    def __init__(self, api_url, api_key):
        self.api_url = api_url
        self.api_key = api_key

    def report(self, project_name, project_version, bom):
        response = requests.put(
            url=f"{self.api_url}/bom",
            headers={"X-API-Key": self.api_key},
            json={
                "projectName": project_name,
                "projectVersion": project_version,
                "autoCreate": True,
                "bom": base64.b64encode(bom).decode(),
            },
        )
        if response.status_code >= 400:
            logging.error(
                "Got error uploading BOM to DependencyTrack: %s", response.text
            )
        logging.debug(response.text)
