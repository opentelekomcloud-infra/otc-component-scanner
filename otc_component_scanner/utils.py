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
import requests
from urllib.parse import urljoin

from git import exc
from git import Repo


class Session(requests.Session):
    def __init__(self, base_url=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.base_url = base_url

    def request(self, method, url, *args, **kwargs):
        if not url.startswith("http"):
            url = urljoin(self.base_url, url)
        return super().request(method, url, *args, **kwargs)


def checkout_repo(canonical_name, clone_url, work_dir):
    workdir = pathlib.Path(work_dir)
    workdir.mkdir(exist_ok=True)
    repo_dir = pathlib.Path(workdir, canonical_name)

    if repo_dir.exists():
        logging.debug(f"Repository {canonical_name} already checked out")
        try:
            git_repo = Repo(repo_dir)
            git_repo.remotes.origin.fetch()
            # git_repo.heads.main.checkout()
            # git_repo.remotes.origin.pull()
        except exc.InvalidGitRepositoryError:
            logging.error("Existing repository checkout is bad")
            repo_dir.rmdir()

    if not repo_dir.exists():
        try:
            repo_dir.mkdir(parents=True, exist_ok=True)
            git_repo = Repo.clone_from(clone_url, repo_dir)
        except Exception:
            logging.error(f"Error cloning repository {clone_url}")
            return
    return repo_dir
