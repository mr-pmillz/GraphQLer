from pathlib import Path
import yaml
import json
import shutil
import os
import stat


def _output_path(file_path: str | Path) -> tuple[Path, Path]:
    """Keep writes inside the active run and reject linked or non-regular files."""
    from graphqler.output import active_store
    from graphqler.output.files import ensure_directory
    path = Path(os.path.abspath(file_path))
    store = active_store()
    root = store.directory if store else path.parent.resolve()
    ensure_directory(path.parent, root)
    if path.is_symlink():
        raise ValueError("Refusing to write an output symlink")
    if path.exists():
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("Output must be a regular file with a single link")
    return path, root


def initialize_file(file_path: str | Path):
    """Initialize file_path with an empty file creating any folders along the way

    Args:
        file_path (str | Path): The path to the file
    """
    from graphqler.output.files import atomic_writer
    path, root = _output_path(file_path)
    with atomic_writer(path, root):
        pass


def intialize_file_if_not_exists(file_path: Path):
    """Initialize file_path with an empty file creating any folders along the way if it does not exist

    Args:
        file_path (Path): The path to the file
    """
    _output_path(file_path)
    if not file_path.exists():
        initialize_file(file_path)


def recreate_path(dir_path: Path):
    """Recreate a directory

    Args:
        dir_path (Path): The directory path
    """
    # Convert the path to a Path object
    path = Path(dir_path)
    get_or_create_directory(path)

    # Remove the directory if it exists
    shutil.rmtree(path, ignore_errors=True)

    # Re-create the directory
    path.mkdir(parents=True, exist_ok=True)


def get_or_create_directory(directory_path: str | Path) -> Path:
    """Gets a directory if it exists, otherwise creates it

    Args:
        directory_path (str | Path): directory path

    Returns:
        Path: The directory path
    """
    if isinstance(directory_path, str):
        directory_path = Path(directory_path)
    from graphqler.output import active_store
    from graphqler.output.files import ensure_directory
    absolute = Path(os.path.abspath(directory_path))
    store = active_store()
    root = store.directory if store else absolute.parent.resolve()
    ensure_directory(absolute, root)
    return directory_path


def get_or_create_file(file_path: Path) -> Path:
    """Gets a file if it exists, otherwise creates it

    Args:
        file_path (Path): File path

    Returns:
        Path: The file path
    """
    _output_path(file_path)
    if not file_path.exists():
        initialize_file(file_path)
    return file_path


def open_output(file_path: str | Path, mode: str = "w", **options):
    """Open a guarded legacy output file for writing or appending."""
    if mode not in {"w", "a", "wb", "ab"}:
        raise ValueError("Output files must be opened for writing or appending")
    return open(get_or_create_file(Path(file_path)), mode, **options)


def write_json_to_file(contents: dict, output_file: str | Path):
    """Write JSON to a file

    Args:
        contents (dict): Contents of the JSON
        output_file (str): Output file path
    """
    from graphqler.output.files import atomic_writer
    path, root = _output_path(output_file)
    with atomic_writer(path, root) as file_handle:
        json.dump(contents, file_handle, indent=4)


def write_dict_to_yaml(contents: dict, output_file: str | Path):
    """Writes dict to YAML file

    Args:
        contents (dict): Contents of the YAML
        output_file (str): Output file path
    """
    yaml_data = yaml.dump(contents, default_flow_style=False)
    from graphqler.output.files import atomic_writer
    path, root = _output_path(output_file)
    with atomic_writer(path, root) as yaml_file:
        yaml_file.write(yaml_data)


def read_yaml_to_dict(read_path: Path) -> dict:
    """Reads yaml file to dict

    Args:
        read_path (Path): Path of the yaml file

    Returns:
        dict: Dictionary of the YAML file contents
    """
    return yaml.safe_load(read_path.read_text())


def get_graphqler_root() -> Path:
    """Gets graphqler's root

    Returns:
        Path: Graphqler root
    """
    return Path(__file__).parent.parent


def get_project_root() -> Path:
    """Gets the project root

    Returns:
        Path: The project root
    """
    return Path(__file__).parent.parent.parent
