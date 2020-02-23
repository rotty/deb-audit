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

    def is_ignored(self):
        return self.nodsa is not None

class Cache:
    """Keeps data from UDD relating to security issues for a Debian release and architecture."""
    def __init__(self, *, directory, release, architectures, message_sink=None):
        self._directory = directory
        self._archs = architectures
        self._release = release
        self._source_maps = {}
        self._issue_map = {}
        if message_sink is None:
            message_sink = lambda _: None
        self._message = message_sink
        self._load()

    def is_complete(self):
        """Check if all required cache files are present on disk."""
        return all(path.exists(filename) for filename in self._cache_files())

    def last_updated(self):
        """Returns the time the cache was last updated, or `None` if it is not present.

        The timestamp returned is an epoch-based number of seconds.
        """
        if not self.is_complete():
            return None
        return min(path.getmtime(filename) for filename in self._cache_files())

    def _load(self):
        """Load existing parts of the cache from disk."""
        # It's somewhat unfortunate that we are limited to line-delimited JSON here, but it seems
        # Python's json.load always tries to parse the complete input.
        issue_map = {}
        try:
            with open(self._issue_cache()) as cache_file:
                for line in cache_file:
                    json_dict = json.loads(line)
                    issue = Issue(**json_dict)
                    issue_map.setdefault(issue.source, []).append(issue)
        except FileNotFoundError:
            pass
        source_maps = {}
        for arch in self._archs:
            try:
                with open(self._source_map_cache(arch)) as cache_file:
                    json_map = json.load(cache_file)
            except FileNotFoundError:
                continue
            source_map = {}
            for package, versions in json_map.items():
                # Tupelize items for symmetry with `fetch_source_map`
                # pylint: disable=unnecessary-comprehension
                source_map[package] = [(version, source) for version, source in versions]
            source_maps[arch] = source_map
        self._issue_map = issue_map
        self._source_maps = source_maps

    def dump(self):
        """Dump the cache to disk."""
        os.makedirs(self._directory, exist_ok=True)
        for arch in self._archs:
            with atomic_write(self._source_map_cache(arch), overwrite=True) as output:
                json.dump(self._source_maps[arch], output)
        with atomic_write(self._issue_cache(), overwrite=True) as output:
            for issues in self._issue_map.values():
                for issue in issues:
                    json.dump(dataclasses.asdict(issue), output)
                    output.write('\n')

    def load_missing(self, conn):
        """Load missing cache contents from UDD."""
        with conn.cursor() as cursor:
            source_maps = {}
            for arch in self._archs:
                if arch not in self._source_maps:
                    self._message(f'Loading source map for {self._release} {arch}')
                    self._source_maps[arch] = fetch_source_map(cursor,
                                                               release=self._release,
                                                               architecture=arch)
            if self._issue_map is None:
                self._message(f'Loading issues for {self._release}')
                issue_map = {}
                for issue in fetch_issues(cursor, release=self._release):
                    issue_map.setdefault(issue.source, []).append(issue)
                self._issue_map = issue_map

    def is_known(self, *, package, architecture):
        """Check if the cache contains information about a binary package."""
        return package in self._source_maps[architecture]

    def issues(self, *, package, architecture):
        """Yield all issues in a binary package."""
        versions = self._source_maps[architecture][package]
        sources = {source for _version, source in versions}
        for source in sources:
            for issue in self._issue_map.get(source, []):
                yield issue

    def _cache_files(self):
        return [self._source_map_cache(arch) for arch in self._archs] + [self._issue_cache()]

    def _issue_cache(self):
        return path.join(self._directory, f'{self._release}-issues.json')

    def _source_map_cache(self, arch):
        return path.join(self._directory, f'{self._release}-{arch}.source-map.json')

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

@dataclass
class Package:
    name: str
    version: str
    architecture: str

    @staticmethod
    def from_control(control):
        return Package(name=control['Package'],
                       version=control['Version'],
                       architecture=control['Architecture'])

    def __str__(self):
        return f'{self.name} {self.architecture} {self.version}'

def scan_packages(filenames):
    """Parse names and versions from .deb files.

    Returns a list of `Package`.
    """
    packages = []
    for filename in filenames:
        deb = DebFile(filename)
        control = deb.debcontrol()
        packages.append(Package.from_control(deb.debcontrol()))
    return packages

@dataclass
class Summary:
    """A summary of issues found in for a package."""
    issues_fixed: list
    issues_present: list
    issues_ignored: list

    @staticmethod
    def from_issues(issues, *, version=None):
        """Construct a summary from a list of issues.

        If `version` is supplied, consider it to determine if a issue is fixed. If not supplied, all
        issues will be considered unfixed (i.e. present or ignored).
        """
        fixed, present, ignored = [], [], []
        for issue in issues:
            if version:
                if issue.is_present_in(version):
                    if issue.is_ignored():
                        ignored.append(issue)
                    else:
                        present.append(issue)
                else:
                    fixed.append(issue)
            elif issue.is_ignored():
                ignored.append(issue)
            else:
                present.append(issue)
        return Summary(issues_fixed=fixed, issues_present=present, issues_ignored=ignored)

class Checker:
    """Implements the deb-audit CLI logic."""

    def __init__(self, *, release, files, show_all=False, verbose=False):
        self._release = release
        self._files = files
        self._show_all = show_all
        self._verbose = verbose

    def run(self):
        packages = scan_packages(self._files)
        cache_dir = path.expanduser('~/.cache/deb-audit')
        archs = {pkg.architecture for pkg in packages}
        cache = Cache(directory=cache_dir, release=self._release, architectures=archs,
                      message_sink=self._message)
        if cache.is_complete():
            updated = cache.last_updated()
            local_time = time.strftime('%Y-%m-%d %H:%M %z', time.localtime(updated))
            self._message(f'Loading cache (last update: {local_time})')
        else:
            self._message('Cache incomplete, loading data from UDD')
            with udd_connect() as conn:
                cache.load_missing(conn)
            self._message('Data loaded sucessfully, dumping to disk')
            cache.dump()
        total_present = 0
        total_unknown = 0
        for pkg in packages:
            if not cache.is_known(package=pkg.name, architecture=pkg.architecture):
                print(f'Unknown in release "{self._release}": {pkg} ')
                total_unknown += 1
                continue
            issues = cache.issues(package=pkg.name, architecture=pkg.architecture)
            summary = Summary.from_issues(issues, version=pkg.version)
            n_present = len(summary.issues_present)
            n_ignored = len(summary.issues_ignored)
            n_fixed = len(summary.issues_fixed)
            if self._show_all or n_present > 0:
                print(f'{pkg}: {n_present} present, {n_ignored} ignored, {n_fixed} fixed')
            total_present += n_present
        if total_present > 0:
            self._message(f'Found {total_present} not-ignored issues')
            return False
        elif total_unknown > 0:
            self._message(f'Found {total_unknown} unknown issues')
            return False
        else:
            self._message(f'No non-ignored issues found')
            return True

    def _message(self, msg):
        """In verbose mode, issue an informational message to stderr."""
        if self._verbose:
            print('* ' + msg, file=sys.stderr)

def main():
    """Top-level entry point."""
    parser = argparse.ArgumentParser(description='Check Debian packages for know vulnerabilities')
    parser.add_argument('-r', '--release', type=str, default='buster',
                        help='Debian release (default "buster")')
    parser.add_argument('--verbose', action='store_true',
                        help='Show informational messages')
    parser.add_argument('-a', '--show-all', action='store_true',
                        help='Show stats for clean packages as well')
    parser.add_argument('files', metavar='FILE', type=str, nargs='+', help='Debian package names')
    args = parser.parse_args()
    checker = Checker(release=args.release, files=args.files,
                      show_all=args.show_all, verbose=args.verbose)
    if checker.run():
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == '__main__':
    main()
