"""
DNSKit
Copyright (C) 2024 Ian Spence

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""
from pathlib import Path
from datetime import datetime
import subprocess
import sys

license_header_template = ""
with open(".github/license-header.txt", "r") as file:
    license_header_template = file.read().rstrip()

def get_license_header(year):
    return license_header_template.replace("##YEAR##", year)

def get_file_year(filepath):
    year = datetime.now().strftime("%Y")
    try:
        result = subprocess.run(["git", "--no-pager", "log", "-1", "--pretty=\"format:%ci\"", "--", filepath], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        year = result.stdout.split("-")[0]
    except Exception as e:
        pass
    return year

def check_file_header(filepath, offset, prefix):
    contents = ""
    with open(filepath, "r") as file:
        contents = file.read()

    lines = contents.split("\n")

    year = get_file_year(filepath)

    header = get_license_header(year)
    header_lines = header.split('\n')

    if len(lines) + offset < len(header_lines):
        return False

    i = 0
    while i < len(header_lines)-1:
        if lines[i + offset] != prefix + header_lines[i]:
            return False
        i = i + 1

    return True

all_passed = True

for source_dir in [ "Sources", "Tests", ".github" ]:
    swift_files = list(Path(source_dir).rglob("*.[Ss][Ww][Ii][Ff][Tt]"))
    go_files = list(Path(source_dir).rglob("*.[Gg][Oo]"))
    py_files = list(Path(source_dir).rglob("*.[Pp][Yy]"))

    for filepath in swift_files:
        if not check_file_header(filepath, 0, "// "):
            print(str(filepath) + ": Invalid license header", file=sys.stderr)
            all_passed = False

    for filepath in go_files:
        if not check_file_header(filepath, 1, ""):
            print(str(filepath) + ": Invalid license header", file=sys.stderr)
            all_passed = False

    for filepath in py_files:
        if not check_file_header(filepath, 1, ""):
            print(str(filepath) + ": Invalid license header", file=sys.stderr)
            all_passed = False

if not all_passed:
    exit(1)
