"""Build real artifacts from isolated Git histories, tags, and exported sources."""

import os
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

from scripts.verify_dist import verify_distributions

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def repository(tmp_path):
    root = tmp_path / "repository"
    root.mkdir()
    for name in ("pyproject.toml", "uv.lock", "README.md", "LICENSE", ".gitignore", ".gitattributes", ".git_archival.txt"):
        shutil.copyfile(ROOT / name, root / name)
    (root / "graphqler").mkdir()
    (root / "graphqler/__init__.py").write_text('"""Version fixture."""\n')
    git(root, "init")
    git(root, "add", ".")
    git(root, "commit", "-m", "Initial version fixture")
    git(root, "tag", "v9.8.7")
    return root


def environment():
    env = {key: value for key, value in os.environ.items() if not key.startswith(("SETUPTOOLS_SCM_", "VCS_VERSIONING_", "GIT_"))}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    return env


def git(root, *arguments):
    return subprocess.run(["git", "-c", "user.name=Version test", "-c", "user.email=version@example.invalid",
                           "-c", "commit.gpgsign=false", *arguments], cwd=root, env=environment(), check=True, capture_output=True)


def build(root, output, *arguments, check=True):
    result = subprocess.run([
        "uv", "build", str(root), "--offline", "--out-dir", str(output),
        "--build-constraints", str(ROOT / "build-constraints.txt"), "--require-hashes", *arguments,
    ], cwd=root, env=environment(), capture_output=True, text=True, timeout=60)
    if check:
        assert result.returncode == 0, result.stdout + result.stderr
    return result


def test_tagged_build_and_sdist_rebuild_preserve_version_without_git(repository, tmp_path):
    output_files = repository / "graphqler-output-private"
    output_files.mkdir()
    (output_files / "request.txt").write_text("Untracked scan data must never enter a distribution")
    output = tmp_path / "tagged"
    build(repository, output)
    assert verify_distributions(output, "v9.8.7") == "9.8.7"
    source = tmp_path / "extracted"
    with tarfile.open(next(output.glob("*.tar.gz")), "r:gz") as archive:
        assert not any("graphqler-output-private" in name for name in archive.getnames())
        archive.extractall(source, filter="data")
    unpacked = source / "graphqler-9.8.7"
    rebuilt = tmp_path / "rebuilt"
    build(unpacked, rebuilt, "--wheel")
    shutil.copyfile(next(output.glob("*.tar.gz")), rebuilt / "graphqler-9.8.7.tar.gz")
    assert verify_distributions(rebuilt, "v9.8.7") == "9.8.7"


def test_commit_and_new_tag_change_versions_without_changing_the_lock(repository, tmp_path):
    (repository / "graphqler/__init__.py").write_text('"""Next commit."""\n')
    git(repository, "add", ".")
    git(repository, "commit", "-m", "Next commit")
    development = tmp_path / "development"
    build(repository, development)
    assert verify_distributions(development).startswith("9.8.8.dev1+g")
    git(repository, "tag", "v9.8.8rc1")
    release = tmp_path / "release"
    build(repository, release)
    assert verify_distributions(release, "v9.8.8rc1") == "9.8.8rc1"
    lock = subprocess.run(["uv", "lock", "--check", "--offline"], cwd=repository, env=environment(), capture_output=True, text=True, timeout=60)
    assert lock.returncode == 0, lock.stderr


def test_git_archive_preserves_tag_version(repository, tmp_path):
    archive_path = tmp_path / "archive.tar"
    git(repository, "archive", "--output", str(archive_path), "HEAD")
    source = tmp_path / "archive"
    with tarfile.open(archive_path) as archive:
        archive.extractall(source, filter="data")
    output = tmp_path / "archived-build"
    build(source, output)
    assert verify_distributions(output, "v9.8.7") == "9.8.7"


def test_source_without_version_provenance_fails_instead_of_inventing_a_release(repository, tmp_path):
    source = tmp_path / "unidentified"
    shutil.copytree(repository, source, ignore=shutil.ignore_patterns(".git", ".git_archival.txt"))
    result = build(source, tmp_path / "unknown-build", check=False)
    assert result.returncode != 0
    assert "version" in result.stderr.lower()
