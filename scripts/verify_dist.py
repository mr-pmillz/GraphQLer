"""Verify that wheel, source archive, installed package, and release tag agree."""

import argparse
import importlib.metadata
import re
import tarfile
import zipfile
from email.parser import BytesParser
from pathlib import Path

from packaging.utils import canonicalize_name, parse_sdist_filename, parse_wheel_filename
from packaging.version import Version


def verify_distributions(directory: Path, tag: str = "", installed: bool = False) -> str:
    """Reject stale or mismatched artifacts before publishing or building an image."""
    wheels, archives = list(directory.glob("*.whl")), list(directory.glob("*.tar.gz"))
    if len(wheels) != 1 or len(archives) != 1:
        raise ValueError("Expected exactly one wheel and one source archive; build into an empty directory")
    with zipfile.ZipFile(wheels[0]) as wheel:
        names = [name for name in wheel.namelist() if re.fullmatch(r"[^/]+\.dist-info/METADATA", name)]
        if len(names) != 1:
            raise ValueError("Wheel must contain exactly one package metadata file")
        wheel_metadata = BytesParser().parsebytes(wheel.read(names[0]))
    with tarfile.open(archives[0], "r:gz") as archive:
        names = [member for member in archive if member.name.count("/") == 1 and member.name.endswith("/PKG-INFO") and member.isfile()]
        if len(names) != 1:
            raise ValueError("Source archive must contain exactly one package metadata file")
        source = archive.extractfile(names[0])
        if source is None:
            raise ValueError("Source archive metadata is unreadable")
        with source:
            source_metadata = BytesParser().parsebytes(source.read())
    versions = []
    for metadata in (wheel_metadata, source_metadata):
        if len(metadata.get_all("Name", [])) != 1 or canonicalize_name(metadata["Name"]) != "graphqler":
            raise ValueError("Artifacts must contain GraphQLer")
        if len(metadata.get_all("Version", [])) != 1:
            raise ValueError("Artifact version is missing or ambiguous")
        versions.append(Version(metadata["Version"]))
    for name, version in (parse_wheel_filename(wheels[0].name)[:2], parse_sdist_filename(archives[0].name)):
        if name != "graphqler":
            raise ValueError("Artifact filenames must identify GraphQLer")
        versions.append(version)
    if installed:
        versions.append(Version(importlib.metadata.version("GraphQLer")))
    if len(set(versions)) != 1:
        raise ValueError(f"Artifact and package versions disagree: {versions}")
    version = str(versions[0])
    if tag and (not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:(?:a|b|rc)[0-9]+)?", tag) or tag != "v" + version):
        raise ValueError(f"Release tag {tag!r} does not match Git-derived artifact version {version!r}")
    return version


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--tag", default="", help="expected release tag, e.g. v2.4.2")
    parser.add_argument("--installed", action="store_true", help="also compare the installed package version")
    args = parser.parse_args()
    try:
        print(verify_distributions(args.directory, args.tag, args.installed))
    except (ValueError, OSError) as error:
        parser.exit(1, f"Distribution verification failed: {error}\n")
