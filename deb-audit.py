import dataclasses
from dataclasses import dataclass
from os import path
import json

import psycopg2

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

class Cache:
    def __init__(self, *, release, architecture):
        self._arch = architecture
        self._release = release
        self._source_map = {}
        self._issue_map = {}

    def load(self, directory):
        # It's somewhat unfortunate that we are limited to line-delimited JSON here, but it seems
        # Python's json.load always tries to parse the complete input.
        issue_map = {}
        with open(path.join(directory, f'{self._release}-issues.json')) as f:
            for line in f:
                json_dict = json.loads(line)
                issue = Issue(**json_dict)
                issue_map.setdefault(issue.source, []).append(issue)
        source_map = {}
        with open(path.join(directory, f'{self._release}-{self._arch}.source-map.json')) as f:
            json_map = json.load(f)
        for package, versions in json_map.items():
            source_map[package] = [(version, source) for version, source in versions]
        self._issue_map = issue_map
        self._source_map = source_map

    def dump(self, *, directory):
        pass

    def refresh(self, conn):
        source_map = fetch_source_map(conn, release=self)
        issue_map = {}
        for issue in fetch_issues(conn, release=self._release):
            issue_map.setdefault(issue.source, []).append(issue)
        self._source_map = source_map
        self._issues_map = issue_map

    def issues(self, *, package):
        versions = self._source_map[package]
        sources = {source for _version, source in versions}
        for source in sources:
            for issue in self._issue_map.get(source, []):
                yield issue

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

def refresh_cache(conn):
    source_map = fetch_source_map(conn,
                                  release='buster',
                                  architecture='amd64')
    with open('buster-amd64.source-map.json', mode='w') as f:
        json.dump(source_map, f)
    with open('buster-issues.json', mode='w') as f:
        for issue in fetch_issues(conn, release='buster'):
            json.dump(dataclasses.asdict(issue), f)
            f.write('\n')

def udd_connect():
    conn = psycopg2.connect(host='udd-mirror.debian.net',
                            user='udd-mirror',
                            password='udd-mirror',
                            dbname='udd')
    conn.set_client_encoding('UTF8')
    return conn

if __name__ == '__main__':
    cache = Cache(release='buster', architecture='amd64')
    cache.load('.')
    for issue in cache.issues(package='zlib1g'):
        print(issue)
