import os
import copy
import threading
from functools import wraps
import json
import math
from pathlib import Path
import tomllib

from graphqler import config
from graphqler.utils.file_utils import get_graphqler_root


pipeline_lock = threading.RLock()


def isolated_run(function):
    """Serialize embedded runs and restore credentials/configuration even on failure."""
    @wraps(function)
    def run(*args, **kwargs):
        with pipeline_lock:
            baseline = {key: copy.deepcopy(value) for key, value in vars(config).items() if key.isupper()}
            try:
                return function(*args, **kwargs)
            finally:
                for key, value in baseline.items():
                    setattr(config, key, value)
                from graphqler.utils.request_utils import reset_session
                from graphqler.utils.logging_utils import reset_loggers
                reset_session()
                reset_loggers()
    return run


def write_config_to_toml(path: str) -> None:
    """Write current live-config values to a TOML file.

    Reads ``examples/config.toml`` to discover the canonical set of
    user-configurable keys — no static list required.  For each key in the
    template, the current value is read from the live ``config`` module so
    any in-process changes are captured.  Keys absent from the live module
    fall back to the template's default value.

    Sensitive fields (``LLM_API_KEY``, ``IDOR_SECONDARY_AUTH``, ``AUTHORIZATION``)
    are always written as empty strings so that secrets provided via CLI flags
    or environment variables are not accidentally persisted to disk.
    """
    # Fields that must never be written to disk
    _REDACTED_FIELDS = {"LLM_API_KEY", "IDOR_SECONDARY_AUTH", "AUTHORIZATION"}

    template_path = get_graphqler_root() / "examples" / "config.toml"
    with open(template_path, "rb") as fh:
        template: dict = tomllib.load(fh)

    lines = ["# GraphQLer configuration\n"]
    for key, template_value in template.items():
        if key == "CUSTOM_HEADERS":
            continue  # written as a TOML section below
        if key in _REDACTED_FIELDS:
            lines.append(f'{key} = ""\n')
            continue
        value = getattr(config, key, template_value)
        if isinstance(value, bool):
            lines.append(f"{key} = {'true' if value else 'false'}\n")
        elif isinstance(value, (int, float)):
            lines.append(f"{key} = {value}\n")
        elif isinstance(value, list):
            # Emit a proper TOML inline array; strings are quoted and escaped
            def _toml_item(item) -> str:
                if isinstance(item, str):
                    return json.dumps(item, ensure_ascii=False)
                if isinstance(item, bool):
                    return str(item).lower()
                return str(item)
            items = ", ".join(_toml_item(item) for item in value)
            lines.append(f"{key} = [{items}]\n")
        elif value is None:
            lines.append(f'{key} = ""\n')
        else:
            lines.append(f'{key} = {json.dumps(str(value), ensure_ascii=False)}\n')

    lines.append("\n[CUSTOM_HEADERS]\n")
    from graphqler.output.store import _SENSITIVE_HEADER
    headers: dict = getattr(config, "CUSTOM_HEADERS", None) or template.get("CUSTOM_HEADERS", {})
    for k, v in headers.items():
        if _SENSITIVE_HEADER.search(k):
            continue
        lines.append(f'{json.dumps(k, ensure_ascii=False)} = {json.dumps(str(v), ensure_ascii=False)}\n')

    from graphqler.output import active_store
    from graphqler.output.files import atomic_writer
    output = Path(path).absolute()
    store = active_store()
    root = store.output_root if store else output.parent.resolve()
    with atomic_writer(output, root) as fh:
        fh.writelines(lines)


def parse_config(config_obj: str | dict) -> dict:
    """
    Parse the config, and return the dictionary.
    If it's a dictionary, just parses the config object directly
    Otherwise parses it out of a TOML file
    """
    config = {}
    if isinstance(config_obj, dict):
        config = config_obj
    elif isinstance(config_obj, str):
        with open(config_obj, "rb") as f:
            config = tomllib.load(f)

    if len(config.keys()) == 0:
        raise ValueError("Configuration must contain at least one setting")

    return config


def set_config(new_config: dict):
    """Sets config to the new file using reflection on the constants module

    Args:
        new_config (dict): The configuration dictionary
    """
    for k, v in new_config.items():
        if k.isupper() and hasattr(config, k):
            setattr(config, k, v)
        else:
            print(f"(!) Unknown configuration {k}, skipping it")
    from graphqler.utils.request_utils import reset_session
    reset_session()


def validate_config() -> None:
    """Reject invalid resource limits before starting a worker or network request."""
    for key in ("REQUEST_TIMEOUT", "MAX_TIME"):
        value = getattr(config, key)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
            raise ValueError(f"{key} must be finite and positive")
    for key in ("MAX_RESPONSE_BYTES", "MAX_FUZZING_ITERATIONS"):
        value = getattr(config, key)
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"{key} must be a positive integer")
    if not isinstance(config.TIME_BETWEEN_REQUESTS, (int, float)) or not math.isfinite(config.TIME_BETWEEN_REQUESTS) or config.TIME_BETWEEN_REQUESTS < 0:
        raise ValueError("TIME_BETWEEN_REQUESTS must be finite and nonnegative")
    if not isinstance(config.CUSTOM_HEADERS, dict) or not isinstance(config.PROFILES, dict):
        raise ValueError("CUSTOM_HEADERS and PROFILES must be dictionaries")


def generate_new_config(config_file_to_write: str) -> None:
    """Generates the new config file by copying from static/config.toml

    Args:
        config_file_to_write (str): The config file to write
    """
    # copy from the base path of the graphqler package
    project_root = get_graphqler_root()
    from graphqler.output import active_store
    from graphqler.output.files import atomic_writer
    output = Path(config_file_to_write).absolute()
    store = active_store()
    root = store.output_root if store else output.parent.resolve()
    with atomic_writer(output, root) as target:
        target.write((project_root / "examples" / "config.toml").read_text(encoding="utf-8"))


def does_config_file_exist_in_path(path: str) -> bool:
    """Checks if the config file exists in the path

    Args:
        path (str): The path to check

    Returns:
        bool: Whether the config file exists
    """
    return os.path.exists(f"{path}/{config.CONFIG_FILE_NAME}")
