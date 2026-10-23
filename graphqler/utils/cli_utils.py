from graphqler import config
from pathlib import Path
import json
from urllib.parse import urlsplit, urlunsplit


def set_auth_token_constant(auth_argument: str) -> None:
    """Sets the constants for auth token argument.
       If it has a space, it will be used as is, otherwise it will be prepended with "Bearer "

    Args:
        auth_token (str): The auth token argument
    """
    if len(auth_argument.split(" ")) >= 2:
        config.AUTHORIZATION = auth_argument
    else:
        config.AUTHORIZATION = f"Bearer {auth_argument}"
    from graphqler.utils.request_utils import reset_session
    reset_session()


def set_idor_auth_token_constant(auth_argument: str) -> None:
    """Sets the secondary (attacker) auth token used for chain-based IDOR testing.
       If the value already contains a space (e.g. "Bearer …"), it is used as-is;
       otherwise it is prefixed with "Bearer ".

    Args:
        auth_argument (str): The secondary auth token argument
    """
    if len(auth_argument.split(" ")) >= 2:
        config.IDOR_SECONDARY_AUTH = auth_argument
    else:
        config.IDOR_SECONDARY_AUTH = f"Bearer {auth_argument}"
    from graphqler.utils.request_utils import reset_session
    reset_session()


def is_compiled(path: str | Path) -> bool:
    """Require nonempty compiled files and a completed marker when one is present.

    Args:
        path (str): The path to the compiled directory

    Returns:
        bool: True when compilation artifacts are ready for reuse.
    """
    if path is None:
        return False
    path = Path(path)
    marker = path / config.COMPILED_DIR_NAME / "target.json"
    if marker.exists():
        try:
            if json.loads(marker.read_text(encoding="utf-8")).get("status") != "completed":
                return False
        except (ValueError, OSError, AttributeError):
            return False
    return all((path / name).is_file() and (path / name).stat().st_size > 0 for name in (
        config.COMPILED_OBJECTS_FILE_NAME, config.COMPILED_QUERIES_FILE_NAME,
        config.COMPILED_MUTATIONS_FILE_NAME, config.INTROSPECTION_RESULT_FILE_NAME,
    ))


def compiled_target(path: str | Path, target: str) -> str:
    """Reuse a discovered endpoint only for the URL that produced its schema."""
    from graphqler.discovery import _origin, validate_url
    from graphqler.output.redaction import Redactor
    target = validate_url(target)
    marker = Path(path) / config.COMPILED_DIR_NAME / "target.json"
    if not marker.exists():
        return target  # Legacy compilations have no target binding.
    data = json.loads(marker.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("status") != "completed":
        raise ValueError("Compilation is incomplete; compile this target again")
    clean_target = Redactor().url(target)
    endpoint = validate_url(data["endpoint"])
    if clean_target not in {data["requested"], endpoint} or _origin(target) != _origin(endpoint):
        raise ValueError("Compiled artifacts belong to a different target; use a separate output directory or compile again")
    if clean_target == endpoint:
        return target
    # Query credentials come from this invocation, never the saved redacted marker.
    return urlunsplit(urlsplit(target)._replace(path=urlsplit(endpoint).path))


def write_compilation_target(path: str | Path, target: str, status: str) -> None:
    """Persist compilation identity without persisting query credentials."""
    from graphqler.output import active_store
    from graphqler.output.files import atomic_writer
    from graphqler.output.redaction import Redactor
    store = active_store()
    redactor = store.redactor if store else Redactor()
    requested = getattr(store, "requested_target", target)
    directory = Path(path).resolve()
    with atomic_writer(directory / config.COMPILED_DIR_NAME / "target.json", directory) as output:
        json.dump({"status": status, "requested": redactor.url(requested), "endpoint": redactor.url(target)}, output)
        output.write("\n")
