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


class Zuul:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = utils.Session(base_url=self.base_url)

    def get_tenants(self):
        rsp = self.session.get("/api/tenants")
        return rsp.json()

    def get_projects(self, tenant):
        rsp = self.session.get(f"/api/tenant/{tenant}/projects")
        return rsp.json()
