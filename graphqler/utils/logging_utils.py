import logging
from graphqler import config
from pathlib import Path
from graphqler.utils.singleton import singleton
from graphqler.utils.file_utils import get_or_create_directory, get_or_create_file, initialize_file


def reset_loggers() -> None:
    """Close previous scan file handlers while preserving TUI/embedding handlers."""
    for name in list(logging.Logger.manager.loggerDict):
        if name in {"fuzzer", "compiler", "detector", "idor"} or name.startswith("fuzzer.chain."):
            logger = logging.getLogger(name)
            for handler in list(logger.handlers):
                if isinstance(handler, logging.FileHandler):
                    handler.close()
                    logger.removeHandler(handler)
    getattr(Logger, "reset")()


@singleton
class Logger:
    fuzzer_logger = None
    compiler_logger = None
    detector_logger = None
    idor_logger = None
    fuzzer_log_path = Path(config.OUTPUT_DIRECTORY) / Path(config.FUZZER_LOG_FILE_PATH)
    compiler_log_path = Path(config.OUTPUT_DIRECTORY) / Path(config.COMPILER_LOG_FILE_PATH)
    detector_log_path = Path(config.OUTPUT_DIRECTORY) / Path(config.DETECTOR_LOG_FILE_PATH)
    idor_log_path = Path(config.OUTPUT_DIRECTORY) / Path(config.IDOR_LOG_FILE_PATH)

    def __init__(self):
        self.fuzzer_log_path = Path(config.OUTPUT_DIRECTORY) / Path(config.FUZZER_LOG_FILE_PATH)
        self.compiler_log_path = Path(config.OUTPUT_DIRECTORY) / Path(config.COMPILER_LOG_FILE_PATH)
        self.detector_log_path = Path(config.OUTPUT_DIRECTORY) / Path(config.DETECTOR_LOG_FILE_PATH)
        self.idor_log_path = Path(config.OUTPUT_DIRECTORY) / Path(config.IDOR_LOG_FILE_PATH)

    def _select_directory(self, directory: str | Path | None = None) -> None:
        from graphqler.output import active_store
        store = active_store()
        directory = Path(directory if directory is not None else store.directory if store else config.OUTPUT_DIRECTORY)
        for name in ("fuzzer", "compiler", "detector", "idor"):
            path = directory / getattr(config, f"{name.upper()}_LOG_FILE_PATH")
            if getattr(self, f"{name}_log_path") != path:
                setattr(self, f"{name}_log_path", path)
                setattr(self, f"{name}_logger", None)

    def get_fuzzer_logger(self) -> logging.Logger:
        """Gets the fuzzer logger. Creates the logger if it doesn't exist, and creates the log file if it doesn't exist

        Returns:
            logging.Logger: The fuzzer logger
        """
        self._select_directory()
        # create the log file if it doesn't exist
        if not self.fuzzer_log_path.exists():
            get_or_create_directory(self.fuzzer_log_path.parent)
            initialize_file(self.fuzzer_log_path)

        # create the logger if it doesn't exist
        if not self.fuzzer_logger or not self.fuzzer_logger.hasHandlers():
            self.fuzzer_logger = self._get_logger("fuzzer", self.fuzzer_log_path)

        # return the logger
        return self.fuzzer_logger

    def get_detector_logger(self) -> logging.Logger:
        """Gets the detector logger. Creates the logger if it doesn't exist, and creates the log file if it doesn't exist

        Returns:
            logging.Logger: The detector logger
        """
        self._select_directory()
        # create the log file if it doesn't exist
        if not self.detector_log_path.exists():
            get_or_create_directory(self.detector_log_path.parent)
            initialize_file(self.detector_log_path)

        # create the logger if it doesn't exist
        if not self.detector_logger or not self.detector_logger.hasHandlers():
            self.detector_logger = self._get_logger("detector", self.detector_log_path)

        # return the logger
        return self.detector_logger

    def get_compiler_logger(self, directory: str | Path | None = None) -> logging.Logger:
        """Gets the compiler logger. Creates the logger if it doesn't exist, and creates the log file if it doesn't exist

        Returns:
            logging.Logger: The compiler logger
        """
        self._select_directory(directory)
        # create the log file if it doesn't exist
        if not self.compiler_log_path.exists():
            get_or_create_directory(self.compiler_log_path.parent)
            initialize_file(self.compiler_log_path)

        # create the logger if it doesn't exist
        if not self.compiler_logger:
            self.compiler_logger = self._get_logger("compiler", self.compiler_log_path)

        # return the logger
        return self.compiler_logger

    def get_idor_logger(self) -> logging.Logger:
        """Gets the IDOR logger. Creates the logger if it doesn't exist, and creates the log file if it doesn't exist

        Returns:
            logging.Logger: The IDOR logger
        """
        self._select_directory()
        # create the log file if it doesn't exist
        if not self.idor_log_path.exists():
            get_or_create_directory(self.idor_log_path.parent)
            initialize_file(self.idor_log_path)

        # create the logger if it doesn't exist
        if not self.idor_logger:
            self.idor_logger = self._get_logger("idor", self.idor_log_path)

        # return the logger
        return self.idor_logger

    def get_chain_logger(self, chain_id: str) -> logging.Logger:
        """Creates (or reuses) a logger that writes to ``logs/chain_logs/<chain_id>/fuzzer.log``.

        The logger name ``fuzzer.chain.<chain_id>`` is unique per chain so multiple chains
        running sequentially each get an independent FileHandler pointing at their own file.

        Args:
            chain_id (str): The UUID of the chain.

        Returns:
            logging.Logger: A logger configured to write to the chain's log file.
        """
        chain_log_dir = Path(config.OUTPUT_DIRECTORY) / config.CHAIN_LOGS_DIR_NAME / chain_id
        get_or_create_directory(chain_log_dir)
        chain_log_path = chain_log_dir / "fuzzer.log"
        if not chain_log_path.exists():
            initialize_file(chain_log_path)
        return self._get_logger(f"fuzzer.chain.{chain_id}", chain_log_path)

    def _get_logger(self, name: str, file_path: str | Path) -> logging.Logger:
        """Gets a logger with the given name, file path, and level. Creates any required directories

        Args:
            name (str): The name of the logger
            file_path (str): The file path of the logged file

        Returns:
            logging.Logger: The logger returned
        """
        file_path = get_or_create_file(Path(file_path))
        logger = logging.getLogger(name)

        # Avoid adding duplicate handlers when the same named logger is requested again
        resolved_path = str(Path(file_path).resolve())
        current_handler = False
        for h in list(logger.handlers):
            if isinstance(h, logging.FileHandler):
                if str(Path(h.baseFilename).resolve()) == resolved_path:
                    current_handler = True
                else:
                    h.close()
                    logger.removeHandler(h)
        if current_handler:
            return logger

        formatter = logging.Formatter("[%(levelname)s][%(asctime)s][%(name)s]:%(message)s", datefmt="%Y-%m-%d %H:%M:%S")
        handler = logging.FileHandler(file_path, mode="w", encoding="utf-8")
        handler.setFormatter(formatter)

        if config.DEBUG:
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.INFO)
        logger.addHandler(handler)

        return logger
