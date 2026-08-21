"""GitLab public release and package-file metadata search; no asset downloads."""

from __future__ import annotations

import os
import re
from urllib.parse import quote, urlencode

import httpx

from ..models import SearchBatch, SearchResult
from .base import SearchProvider, metadata_name_matches, query_anchor, strip_archive_suffix


class GitLabAssetsProvider(SearchProvider):
    name = "gitlab_assets"
    query_capabilities = frozenset({"filename", "identifier", "phrase"})
    projects_per_page = 5
    packages_per_project = 5

    async def search(self, client: httpx.AsyncClient, query: str, limit: int) -> SearchBatch:
        headers = {"Accept": "application/json"}
        if os.getenv("GITLAB_TOKEN"):
            headers["PRIVATE-TOKEN"] = os.environ["GITLAB_TOKEN"]
        output: list[SearchResult] = []
        pages_fetched = 0
        page_size = min(limit, 20)
        anchor = strip_archive_suffix(query_anchor(query), self.archive_extensions).strip()
        if len(anchor) < 3:
            return SearchBatch()
        for page in range(1, self.max_result_pages_per_query + 1):
            if not self.can_make_request():
                return SearchBatch(output, complete=False, pages_fetched=pages_fetched)
            projects = await self.get_json(
                client,
                "https://gitlab.com/api/v4/projects",
                params={"search": anchor, "simple": "true", "per_page": page_size, "page": page},
                headers=headers,
            )
            pages_fetched += 1
            project_rows = projects if isinstance(projects, list) else []
            for project in project_rows[:self.projects_per_page]:
                project_id = project.get("id")
                project_path = str(project.get("path_with_namespace") or "")
                if (
                    project_id is None
                    or not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+", project_path)
                ):
                    continue
                complete = await self._release_assets(
                    client, headers, query, project_id, project_path, output
                )
                if not complete:
                    return SearchBatch(output, complete=False, pages_fetched=pages_fetched)
                complete = await self._package_files(
                    client, headers, query, project_id, project_path, output
                )
                if not complete:
                    return SearchBatch(output, complete=False, pages_fetched=pages_fetched)
            if len(project_rows) < page_size:
                break
        return SearchBatch(output, pages_fetched=pages_fetched)

    async def _release_assets(
        self,
        client: httpx.AsyncClient,
        headers: dict[str, str],
        query: str,
        project_id: int,
        project_path: str,
        output: list[SearchResult],
    ) -> bool:
        if not self.can_make_request():
            return False
        releases = await self.get_json(
            client,
            f"https://gitlab.com/api/v4/projects/{project_id}/releases",
            params={"per_page": 100},
            headers=headers,
        )
        for release in releases if isinstance(releases, list) else []:
            release_url = str(release.get("_links", {}).get("self") or "")
            links = release.get("assets", {}).get("links", [])
            for asset in links:
                filename = str(asset.get("name") or asset.get("direct_asset_path") or "")
                if not metadata_name_matches(filename, query):
                    continue
                asset_url = str(asset.get("direct_asset_url") or asset.get("url") or "")
                if not asset_url:
                    continue
                output.append(SearchResult(
                    url=asset_url,
                    title=filename,
                    excerpt=f"GitLab release asset in {project_path}",
                    provider=self.name,
                    query=query,
                    published=str(release.get("released_at") or release.get("created_at") or ""),
                    source_url=release_url,
                    record_id=f"release:{project_id}:{release.get('tag_name', '')}:{filename}",
                    metadata={
                        "catalog": "gitlab_release",
                        "project_id": project_id,
                        "project_path": project_path,
                        "release_tag": release.get("tag_name"),
                        "release_url": release_url,
                        "file_name": filename,
                        "file_url": asset_url,
                        "link_type": asset.get("link_type"),
                    },
                ))
        return True

    async def _package_files(
        self,
        client: httpx.AsyncClient,
        headers: dict[str, str],
        query: str,
        project_id: int,
        project_path: str,
        output: list[SearchResult],
    ) -> bool:
        if not self.can_make_request():
            return False
        packages = await self.get_json(
            client,
            f"https://gitlab.com/api/v4/projects/{project_id}/packages",
            params={"per_page": self.packages_per_project, "order_by": "created_at", "sort": "desc"},
            headers=headers,
        )
        for package in (packages if isinstance(packages, list) else [])[:self.packages_per_project]:
            package_id = package.get("id")
            if package_id is None:
                continue
            if not self.can_make_request():
                return False
            files = await self.get_json(
                client,
                f"https://gitlab.com/api/v4/projects/{project_id}/packages/{package_id}/package_files",
                params={"per_page": 100},
                headers=headers,
            )
            for file_record in files if isinstance(files, list) else []:
                filename = str(file_record.get("file_name") or "")
                if not metadata_name_matches(filename, query):
                    continue
                package_query = urlencode({"file": str(file_record.get("id") or filename)})
                package_url = (
                    f"https://gitlab.com/{quote(project_path, safe='/')}/-/packages/{package_id}"
                    f"?{package_query}"
                )
                output.append(SearchResult(
                    url=package_url,
                    title=filename,
                    excerpt=f"GitLab package file in {project_path}; size {file_record.get('size', '')}",
                    provider=self.name,
                    query=query,
                    published=str(file_record.get("created_at") or package.get("created_at") or ""),
                    source_url=(
                        f"https://gitlab.com/api/v4/projects/{project_id}/packages/"
                        f"{package_id}/package_files"
                    ),
                    record_id=f"package:{project_id}:{package_id}:{file_record.get('id', filename)}",
                    metadata={
                        "catalog": "gitlab_package",
                        "project_id": project_id,
                        "project_path": project_path,
                        "package_id": package_id,
                        "package_name": package.get("name"),
                        "package_version": package.get("version"),
                        "package_type": package.get("package_type"),
                        "file_id": file_record.get("id"),
                        "file_name": filename,
                        "file_size": file_record.get("size"),
                        "file_sha256": file_record.get("file_sha256"),
                        "file_md5": file_record.get("file_md5"),
                        "file_sha1": file_record.get("file_sha1"),
                    },
                ))
        return True
