import dataclasses
from dataclasses import dataclass
import os
from os import path
import json
import argparse

import psycopg2
# TODO: implement the comparison in pure python, it's not worth pulling in a depedency on native
# code just for that function.
import apt
version_compare = apt.apt_pkg.version_compare

@dataclass
class Issue:
    """A security issue."""
    source: str
    issue: str
    description: str
    scope: str
    bug: int
    fixed_version: str
    status: str

    def is_present_in(self, version):
        return not self.fixed_version or version_compare(version, self.fixed_version) < 0

class Cache:
    def __init__(self, *, directory, release, architecture):
        self._directory = directory
        self._arch = architecture
        self._release = release
        self._source_map = {}
        self._issue_map = {}

    def is_present(self):
        """Check if the cache files are present on disk."""
        return path.exists(self._source_map_cache()) and path.exists(self._issue_cache())

    def load(self):
        # It's somewhat unfortunate that we are limited to line-delimited JSON here, but it seems
        # Python's json.load always tries to parse the complete input.
        issue_map = {}
        with open(self._issue_cache()) as f:
            for line in f:
                json_dict = json.loads(line)
                issue = Issue(**json_dict)
                issue_map.setdefault(issue.source, []).append(issue)
        source_map = {}
        with open(self._source_map_cache()) as f:
            json_map = json.load(f)
        for package, versions in json_map.items():
            source_map[package] = [(version, source) for version, source in versions]
        self._issue_map = issue_map
        self._source_map = source_map

    def dump(self):
        # TODO: use atomic renames
        with open(self._source_map_cache(), mode='w') as f:
            json.dump(self._source_map, f)
        with open(self._issue_cache(), mode='w') as f:
            for issues in self._issue_map.values():
                for issue in issues:
                    json.dump(dataclasses.asdict(issue), f)
                    f.write('\n')

    def load_udd(self, conn):
        """Load the cache contents from UDD."""
        source_map = fetch_source_map(conn, release=self._release, architecture=self._arch)
        issue_map = {}
        for issue in fetch_issues(conn, release=self._release):
            issue_map.setdefault(issue.source, []).append(issue)
        self._source_map = source_map
        self._issue_map = issue_map

    def issues(self, *, package):
        versions = self._source_map[package]
        sources = {source for _version, source in versions}
        for source in sources:
            for issue in self._issue_map.get(source, []):
                yield issue

    def _issue_cache(self):
        return path.join(self._directory, f'{self._release}-issues.json')

    def _source_map_cache(self):
        return path.join(self._directory, f'{self._release}-{self._arch}.source-map.json')

def fetch_source_map(conn, *, release, architecture):
    cursor = conn.cursor()
    cursor.execute("SELECT package, version, source from all_packages"
                   " WHERE distribution = 'debian'"
                   "   AND release = %(release)s"
                   "   AND architecture = %(architecture)s",
                   {'release': release,
                    'architecture': architecture})
    source_map = {}
    while True:
        row = cursor.fetchone()
        if row is None:
            break
        package, version, source = row
        source_map.setdefault(package, []).append((version, source))
    return source_map

def fetch_issues(conn, *, release):
    cursor = conn.cursor()
    cursor.execute("SELECT i.source, i.issue, i.description, i.scope, i.bug, r.fixed_version, r.status "
                   " FROM security_issues AS i"
                   " INNER JOIN security_issues_releases AS r"
                   " ON i.source = r.source AND i.issue = r.issue"
                   " WHERE r.release = %(release)s",
                   {'release': release})
    while True:
        row = cursor.fetchone()
        if row is None:
            break
        source, issue, description, scope, bug, fixed_version, status = row
        yield Issue(source=source,
                    description=description,
                    scope=scope,
                    fixed_version=fixed_version,
                    issue=issue,
                    bug=bug,
                    status=status)

def udd_connect():
    conn = psycopg2.connect(host='udd-mirror.debian.net',
                            user='udd-mirror',
                            password='udd-mirror',
                            dbname='udd')
    conn.set_client_encoding('UTF8')
    return conn

if __name__ == '__main__':
    cache_dir = path.expanduser('~/.cache/deb-audit')
    cache = Cache(directory=cache_dir, release='buster', architecture='amd64')
    if cache.is_present():
        cache.load()
    else:
        os.makedirs(cache_dir)
        with udd_connect() as conn:
            cache.load_udd(conn)
        cache.dump()
    for issue in cache.issues(package='libxml2'):
        if issue.is_present_in('2.9.4+dfsg1-8'):
            print(issue)
