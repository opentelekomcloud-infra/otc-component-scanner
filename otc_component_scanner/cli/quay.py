#!/usr/bin/env python
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


import argparse
import logging
import re


from otc_component_scanner.analyzers.sbom.syft import SyftSbom
from otc_component_scanner.quay import Quay
from otc_component_scanner.reporters.dependencytrack import (
    DependencytrackReporter,
)


def main():
    parser = argparse.ArgumentParser(
        description="Scan images in quay.io."
    )
    parser.add_argument(
        "--namespace",
        default="opentelekomcloud",
        help="Organization name",
    )
    parser.add_argument(
        "--dependencytrack-api-key",
    )
    parser.add_argument("--filter")

    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG)

    quay = Quay()
    dt = DependencytrackReporter(
        api_url="https://dependencytrack.eco.tsi-dev.otc-service.com/api/v1",
        api_key=args.dependencytrack_api_key,
    )

    for repo in quay.repositories(args.namespace):
        logging.debug("Processing repository %s", repo)
        image = f"quay.io/{args.namespace}/{repo['name']}"
        for tag in quay.repository_tags(args.namespace, repo["name"]):
            bom_res = SyftSbom.execute(f"{image}:{tag['name']}")
            logging.debug("Scanning %s:%s", image, tag['name'])
            dt.report(
                project_name=image,
                project_version=tag["name"],
                bom=bom_res["sbom"],
            )
            break


#    for project in zuul.get_projects(args.tenant):
#        if project["type"] != "untrusted":
#            continue
#        if args.filter and not re.search(args.filter, project["name"]):
#            continue
#        logging.debug("Processing repository %s", project["canonical_name"])
#
#        if project["connection_name"] == "gitea":
#            clone_url = (
#                f"ssh://git@gitea.eco.tsi-dev.otc-service.com:2222/"
#                f"{project['name']}"
#            )
#            # git_fqdn = "gitea.eco.tsi-dev.otc-service.com"
#        elif project["connection_name"] == "github":
#            clone_url = f"git@github.com:/{project['name']}"
#        elif project["connection_name"] == "gitlab":
#            clone_url = f"git@git.tsi-dev.otc-service.com/{project['name']}"
#        else:
#            logging.error(
#                f"Repository type {project['name']} is not supported"
#            )
#            continue
#        repo_dir = checkout_repo(
#            project["canonical_name"], clone_url, args.workdir
#        )
#        dt = DependencytrackReporter(
#            api_url="https://dependencytrack.eco.tsi-dev.otc-service.com/api/v1",
#            api_key=args.dependencytrack_api_key,
#        )
#        if repo_dir:
#            res = scanner.scan(repo_dir)
#            if res:
#                logging.debug("Uploading SBOM to DependencyTrack")
#                sbom = None
#                # version = None
#                for sbom_check in ["CycloneDX-py", "Syft"]:
#                    if sbom_check in res and "sbom" in res[sbom_check]:
#                        sbom = res[sbom_check]["sbom"]
#
#                if not sbom:
#                    continue
#                dt.report(
#                    project_name=project["canonical_name"],
#                    project_version="dev",
#                    bom=sbom,
#                )


if __name__ == "__main__":
    main()
