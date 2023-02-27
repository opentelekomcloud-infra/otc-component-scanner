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

from otc_component_scanner import utils


class Quay():
    def __init__(self, base_url="https://quay.io/"):
        self.base_url = base_url
        self.session = utils.Session(base_url=base_url)

    def repositories(self, namespace):
        response = self.session.request(
            method="GET",
            url="/api/v1/repository",
            params={"namespace": namespace, "public": True},
            headers={"Accept": "application/json"}
        )
        if response.status_code >= 400:
            logging.error("Got error fetching repos: %s", response.text)
        data = response.json().get("repositories", [])
        for repo in data:
            yield repo

    def repository_tags(self, namespace, repository):
        response = self.session.request(
            method="GET",
            url=f"/api/v1/repository/{namespace}/{repository}/tag",
            headers={"Accept": "application/json"}
        )
        if response.status_code >= 400:
            logging.error("Got error fetching repos: %s", response.text)
        data = response.json().get("tags", [])
        for tag in data:
            yield tag
