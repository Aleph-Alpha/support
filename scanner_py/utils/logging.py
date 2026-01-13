"""Logging utilities for the scanner package."""

import logging
import sys
from enum import Enum
from typing import Optional


class LogLevel(Enum):
    """Log level enumeration."""
    NONE = "none"
    INFO = "info"
    VERBOSE = "verbose"


# Custom log levels
STEP = 25  # Between INFO and WARNING
RESULT = 24  # Between INFO and WARNING

# Global flag for verbose mode (controls error visibility)
_verbose_mode = False


def is_verbose() -> bool:
    """Check if verbose mode is enabled."""
    return _verbose_mode


class ColoredFormatter(logging.Formatter):
    """Formatter that adds colors and emojis to log messages."""

    COLORS = {
        logging.DEBUG: "\033[36m",    # Cyan
        logging.INFO: "\033[0m",      # Reset
        STEP: "\033[34m",             # Blue
        RESULT: "\033[32m",           # Green
        logging.WARNING: "\033[33m",  # Yellow
        logging.ERROR: "\033[31m",    # Red
        logging.CRITICAL: "\033[35m", # Magenta
    }
    RESET = "\033[0m"

    EMOJIS = {
        logging.DEBUG: "🔍",
        logging.INFO: "ℹ️ ",
        STEP: "📋",
        RESULT: "   -",
        logging.WARNING: "⚠️ ",
        logging.ERROR: "❌",
        logging.CRITICAL: "💥",
    }

    def format(self, record: logging.LogRecord) -> str:
        # Get emoji and color for this level
        emoji = self.EMOJIS.get(record.levelno, "")
        color = self.COLORS.get(record.levelno, self.RESET)

        # Format the message
        formatted = f"{color}{emoji} {record.getMessage()}{self.RESET}"
        return formatted


class PlainFormatter(logging.Formatter):
    """Plain formatter without colors (for non-terminal output)."""

    EMOJIS = {
        logging.DEBUG: "[DEBUG]",
        logging.INFO: "[INFO]",
        STEP: "[STEP]",
        RESULT: "  -",
        logging.WARNING: "[WARN]",
        logging.ERROR: "[ERROR]",
        logging.CRITICAL: "[CRITICAL]",
    }

    def format(self, record: logging.LogRecord) -> str:
        prefix = self.EMOJIS.get(record.levelno, "[LOG]")
        return f"{prefix} {record.getMessage()}"


class VerboseOnlyFilter(logging.Filter):
    """Filter that only shows ERROR/WARNING in verbose mode."""

    def filter(self, record: logging.LogRecord) -> bool:
        # Always show CRITICAL
        if record.levelno >= logging.CRITICAL:
            return True
        
        # In non-verbose mode, suppress ERROR and WARNING
        if not _verbose_mode and record.levelno in (logging.ERROR, logging.WARNING):
            return False
        
        return True


def setup_logging(
    level: LogLevel = LogLevel.INFO,
    use_colors: Optional[bool] = None,
    show_errors: bool = True,
) -> None:
    """
    Set up logging configuration.

    Args:
        level: Desired log level
        use_colors: Whether to use colored output (auto-detect if None)
        show_errors: Whether to show errors (when False, errors only in verbose)
    """
    global _verbose_mode
    
    # Register custom levels
    logging.addLevelName(STEP, "STEP")
    logging.addLevelName(RESULT, "RESULT")

    # Determine log level and verbose mode
    if level == LogLevel.NONE:
        log_level = logging.CRITICAL + 1  # Effectively disable logging
        _verbose_mode = False
    elif level == LogLevel.VERBOSE:
        log_level = logging.DEBUG
        _verbose_mode = True
    else:
        log_level = logging.INFO
        _verbose_mode = False

    # Auto-detect color support
    if use_colors is None:
        use_colors = sys.stderr.isatty()

    # Get root logger
    root_logger = logging.getLogger("scanner")
    root_logger.setLevel(log_level)

    # Remove existing handlers
    root_logger.handlers.clear()

    # Create handler
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(log_level)

    # Add filter to suppress errors in non-verbose mode
    if not show_errors:
        handler.addFilter(VerboseOnlyFilter())

    # Set formatter
    if use_colors:
        handler.setFormatter(ColoredFormatter())
    else:
        handler.setFormatter(PlainFormatter())

    root_logger.addHandler(handler)


def get_logger(name: str = "scanner") -> logging.Logger:
    """
    Get a logger instance.

    Args:
        name: Logger name

    Returns:
        Logger instance
    """
    return logging.getLogger(name)


# Add custom log methods
def log_step(self: logging.Logger, message: str, *args, **kwargs) -> None:
    """Log a step message."""
    if self.isEnabledFor(STEP):
        self._log(STEP, message, args, **kwargs)


def log_result(self: logging.Logger, message: str, *args, **kwargs) -> None:
    """Log a result message."""
    if self.isEnabledFor(RESULT):
        self._log(RESULT, message, args, **kwargs)


def log_success(self: logging.Logger, message: str, *args, **kwargs) -> None:
    """Log a success message."""
    self.info(f"✅ {message}", *args, **kwargs)


def log_verbose(self: logging.Logger, message: str, *args, **kwargs) -> None:
    """Log a verbose message."""
    self.debug(message, *args, **kwargs)


def log_error_verbose(self: logging.Logger, message: str, *args, **kwargs) -> None:
    """Log an error only in verbose mode."""
    if _verbose_mode:
        self.error(message, *args, **kwargs)
    else:
        self.debug(f"[SUPPRESSED ERROR] {message}", *args, **kwargs)


def log_warn_verbose(self: logging.Logger, message: str, *args, **kwargs) -> None:
    """Log a warning only in verbose mode."""
    if _verbose_mode:
        self.warning(message, *args, **kwargs)
    else:
        self.debug(f"[SUPPRESSED WARN] {message}", *args, **kwargs)


# Monkey-patch Logger class to add custom methods
logging.Logger.step = log_step
logging.Logger.result = log_result
logging.Logger.success = log_success
logging.Logger.verbose = log_verbose
logging.Logger.error_verbose = log_error_verbose
logging.Logger.warn_verbose = log_warn_verbose
