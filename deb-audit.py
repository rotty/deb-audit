#!/usr/bin/env python3

# Copyright © 2020 Andreas Rottmann <mail@r0tty.org>

# Author: Andreas Rottmann <mail@r0tty.org>

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 3
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

"""Check debian packages for known security issues.

Queries the Ultimate Debian Database (UDD) for security issues, and allows to checking specific
(binary) package versions for issues.

To avoid querying UDD for each invokation, it maintains a simple JSON-based cache of the required
information.
"""

# Standard library imports
import dataclasses
from dataclasses import dataclass
import os
from os import path
import json
import argparse
import time
import sys

# External dependency imports
from atomicwrites import atomic_write
import psycopg2
# TODO: implement the comparison in pure python, it's not worth pulling in a depedency on native
# code just for that function.
from apt import apt_pkg
from debian.debfile import DebFile

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
    nodsa: str

    def is_present_in(self, version):
        """Check if a security issue is present in a specific version of the package."""
        return not self.fixed_version or apt_pkg.version_compare(version, self.fixed_version) < 0

class Cache:
    """Keeps data from UDD relating to security issues for a Debian release and architecture."""
    def __init__(self, *, directory, release, architecture):
        self._directory = directory
        self._arch = architecture
        self._release = release
        self._source_map = {}
        self._issue_map = {}

    def is_present(self):
        """Check if the cache files are present on disk."""
        return all(path.exists(filename) for filename in self._cache_files())

    def last_updated(self):
        """Returns the time the cache was last updated, or `None` if it is not present.

        The timestamp returned is an epoch-based number of seconds.
        """
        if not self.is_present():
            return None
        return min(path.getmtime(filename) for filename in self._cache_files())

    def load(self):
        """Load the cache from disk."""
        # It's somewhat unfortunate that we are limited to line-delimited JSON here, but it seems
        # Python's json.load always tries to parse the complete input.
        issue_map = {}
        with open(self._issue_cache()) as cache_file:
            for line in cache_file:
                json_dict = json.loads(line)
                issue = Issue(**json_dict)
                issue_map.setdefault(issue.source, []).append(issue)
        source_map = {}
        with open(self._source_map_cache()) as cache_file:
            json_map = json.load(cache_file)
        for package, versions in json_map.items():
            # Tupelize items for symmetry with `fetch_source_map`
            # pylint: disable=unnecessary-comprehension
            source_map[package] = [(version, source) for version, source in versions]
        self._issue_map = issue_map
        self._source_map = source_map

    def dump(self):
        """Dump the cache to disk."""
        os.makedirs(self._directory)
        with atomic_write(self._source_map_cache(), overwrite=True) as output:
            json.dump(self._source_map, output)
        with atomic_write(self._issue_cache(), overwrite=True) as output:
            for issues in self._issue_map.values():
                for issue in issues:
                    json.dump(dataclasses.asdict(issue), output)
                    output.write('\n')

    def load_udd(self, conn):
        """Load the cache contents from UDD."""
        with conn.cursor() as cursor:
            source_map = fetch_source_map(cursor, release=self._release, architecture=self._arch)
            issue_map = {}
            for issue in fetch_issues(cursor, release=self._release):
                issue_map.setdefault(issue.source, []).append(issue)
        self._source_map = source_map
        self._issue_map = issue_map

    def issues(self, *, package):
        """Yield all issues in a binary package."""
        versions = self._source_map[package]
        sources = {source for _version, source in versions}
        for source in sources:
            for issue in self._issue_map.get(source, []):
                yield issue

    def _cache_files(self):
        return [self._source_map_cache(), path.exists(self._issue_cache())]

    def _issue_cache(self):
        return path.join(self._directory, f'{self._release}-issues.json')

    def _source_map_cache(self):
        return path.join(self._directory, f'{self._release}-{self._arch}.source-map.json')

def fetch_source_map(cursor, *, release, architecture):
    """Fetch a mapping from binary to source package names and versions from UDD."""
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

def fetch_issues(cursor, *, release):
    """Fetch the issues for a Debian release from UDD."""
    cursor.execute("SELECT i.source, i.issue, i.description, i.scope, i.bug,"
                   "       r.fixed_version, r.status, r.nodsa"
                   " FROM security_issues AS i"
                   " INNER JOIN security_issues_releases AS r"
                   " ON i.source = r.source AND i.issue = r.issue"
                   " WHERE r.release = %(release)s",
                   {'release': release})
    while True:
        row = cursor.fetchone()
        if row is None:
            break
        source, issue, description, scope, bug, fixed_version, status, nodsa = row
        yield Issue(source=source,
                    description=description,
                    scope=scope,
                    fixed_version=fixed_version,
                    issue=issue,
                    bug=bug,
                    status=status,
                    nodsa=nodsa)

def udd_connect():
    """Connect to the public read-only mirror of UDD."""
    conn = psycopg2.connect(host='udd-mirror.debian.net',
                            user='udd-mirror',
                            password='udd-mirror',
                            dbname='udd')
    conn.set_client_encoding('UTF8')
    return conn

def message(msg):
    """Issue an informational message to stderr."""
    print('* ' + msg, file=sys.stderr)

def scan_packages(filenames):
    """Parse names and versions from .deb files.

    The names must currently all refer to a single architecture, which is returned as first return
    value.
    """
    archs = set()
    versions = []
    for filename in filenames:
        deb = DebFile(filename)
        control = deb.debcontrol()
        name = control['Package']
        version = control['Version']
        archs.add(control['Architecture'])
        versions.append((name, version))
    if len(archs) > 1:
        assert False # FIXME: proper exception
    return archs.pop(), versions

def main():
    """Top-level entry point."""
    parser = argparse.ArgumentParser(description='Check Debian packages for know vulnerabilities')
    parser.add_argument('--release', type=str, default='buster',
                        help='Debian release (default "buster")')
    parser.add_argument('debs', metavar='DEB', type=str, nargs='+', help='Debian package names')
    args = parser.parse_args()
    architecture, pkgs = scan_packages(args.debs)
    cache_dir = path.expanduser('~/.cache/deb-audit')
    cache = Cache(directory=cache_dir, release=args.release, architecture=architecture)
    if cache.is_present():
        updated = cache.last_updated()
        local_time = time.strftime('%Y-%m-%d %H:%M %z', time.localtime(updated))
        message(f'Loading cache (last update: {local_time})')
        cache.load()
    else:
        message('Cache not found, loading data from UDD')
        with udd_connect() as conn:
            cache.load_udd(conn)
        message('Data loaded sucessfully, dumping to disk')
        cache.dump()
    for name, version in pkgs:
        for issue in cache.issues(package=name):
            if issue.is_present_in(version):
                print(issue)

if __name__ == '__main__':
    main()
