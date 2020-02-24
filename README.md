# deb-audit

A command line tool to scan Debian packages for known security issues.

Currently, `deb-audit` scans `.deb` files provided on its command line
for known security issues, as recorded in
[UDD](https://udd.debian.org/). It takes advantage of the kindly
provided [public, unofficial mirror of
UDD](https://udd-mirror.debian.net/).

`deb-audit` caches the obtained information locally, as to reduce load
on the UDD server, and to speed things up. The tool is designed for
checking varying packages and versions, and thus will always query
information about all packages for a particular release/architecture
combination from UDD, so that future queries pertaining to
already-known release/architectures combinations will avoid accessing
UDD completely.

The code is currently not feature-complete, but considered ready for
adventurous users. Please see below for missing features. If you find
a bug, or would like to propose an additional feature not listed
below, please file an
[issue](https://github.com/rotty/deb-audit/issues).

## Missing features

### Planned (aka "known bugs")

- [ ] Automatically update the cache if it goes stale.
- [ ] A man page. In the mean time, refer to the `--help` output and
      the source code.
- [ ] Use the current system's release as a default for `--release`.

### Likely implemented soon

- [ ] JSON output.

### Patches welcome

- [ ] Currently, only Debian releases are supported. It seems
      information about Ubuntu is also present in UDD, but I have not
      yet assessed the viability of and effort required for Ubuntu
      support.

## Example run

This is a run which does not exhibit any issues:

```
% python3 deb-audit.py --show-all \
   python3-atomicwrites_1.1.5-2_all.deb \
   zlib1g_1.2.11.dfsg-1.2_amd64.deb \
   libxml2_2.9.4+dfsg1-8_amd64.deb
python3-atomicwrites all 1.1.5-2: 0 present, 0 ignored, 0 fixed
zlib1g amd64 1:1.2.11.dfsg-1.2: 0 present, 0 ignored, 8 fixed
libxml2 amd64 2.9.4+dfsg1-8: 0 present, 8 ignored, 76 fixed
% echo $?
0
```

## Installation

On a Debian system ("buster" or later), the following should
suffice to install all required dependencies:

```sh
apt install python3-atomicwrites python3-apt python3-debian python3-psycopg2
```

Python 3.7 or newer is required.

A [`Pipfile`](./Pipfile) for [pipenv](https://github.com/pypa/pipenv)
is provided, but it seems it does not work for the apt bindings, but
it should make it obvious which packages are needed; namely:

```sh
pip3 install atomicwrites python-apt python-debian psycopg2
```

With all dependencies installed, you can just run `python3
deb-audit.py` or copy `deb-audit.py` into `$PATH`, making sure it is
executable. The recommended name for the script, if placed on `$PATH`
is `deb-audit`.

## License

Copyright © 2020 Andreas Rottmann

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3 of the License, or (at
your option) any later version.

This program is distributed in the hope that it will be useful, but
*WITHOUT ANY WARRANTY*; without even the implied warranty of
*MERCHANTABILITY* or *FITNESS FOR A PARTICULAR PURPOSE*. See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, see <https://www.gnu.org/licenses>.
