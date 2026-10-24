"""Release verification rejects wrong versions before upload or container builds."""

import io
import tarfile
import zipfile

import pytest

from scripts.verify_dist import verify_distributions


def artifacts(directory, wheel_version="2.4.2", source_version="2.4.2"):
    with zipfile.ZipFile(directory / f"graphqler-{wheel_version}-py3-none-any.whl", "w") as wheel:
        wheel.writestr(f"graphqler-{wheel_version}.dist-info/METADATA", f"Name: GraphQLer\nVersion: {wheel_version}\n")
    with tarfile.open(directory / f"graphqler-{source_version}.tar.gz", "w:gz") as archive:
        metadata = f"Name: GraphQLer\nVersion: {source_version}\n".encode()
        entry = tarfile.TarInfo(f"graphqler-{source_version}/PKG-INFO")
        entry.size = len(metadata)
        archive.addfile(entry, io.BytesIO(metadata))


def test_git_tag_matches_artifact_metadata(tmp_path):
    artifacts(tmp_path)
    assert verify_distributions(tmp_path, "v2.4.2") == "2.4.2"


@pytest.mark.parametrize("tag", ["v2.4.1", "v2.4.2;echo unexpected", "v02.4.2", "release", "v2.4.2+local"])
def test_wrong_or_invalid_release_tag_is_rejected(tmp_path, tag):
    artifacts(tmp_path)
    with pytest.raises(ValueError, match="Release tag"):
        verify_distributions(tmp_path, tag)


def test_stale_distribution_versions_are_rejected(tmp_path):
    artifacts(tmp_path, source_version="2.4.1")
    with pytest.raises(ValueError, match="disagree"):
        verify_distributions(tmp_path)


def test_extra_wheel_from_an_older_build_is_rejected(tmp_path):
    artifacts(tmp_path)
    (tmp_path / "graphqler-2.4.1-py3-none-any.whl").touch()
    with pytest.raises(ValueError, match="exactly one"):
        verify_distributions(tmp_path)
