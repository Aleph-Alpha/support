"""Subprocess utilities with timeout support."""

import subprocess
import shutil
from dataclasses import dataclass
from typing import Optional, List, Union
from .logging import get_logger, is_verbose

logger = get_logger(__name__)


@dataclass
class CommandResult:
    """Result of a command execution."""
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def success(self) -> bool:
        """Check if command was successful."""
        return self.returncode == 0 and not self.timed_out


def run_command(
    cmd: Union[str, List[str]],
    timeout: Optional[int] = None,
    capture_output: bool = True,
    check: bool = False,
    cwd: Optional[str] = None,
    env: Optional[dict] = None,
    shell: bool = False,
) -> CommandResult:
    """
    Run a command with optional timeout.

    Args:
        cmd: Command to run (string or list of arguments)
        timeout: Timeout in seconds (None for no timeout)
        capture_output: Whether to capture stdout/stderr
        check: Whether to raise exception on non-zero exit
        cwd: Working directory
        env: Environment variables
        shell: Whether to run in shell mode

    Returns:
        CommandResult with stdout, stderr, and return code
    """
    if isinstance(cmd, str) and not shell:
        cmd = cmd.split()

    logger.debug(f"Running command: {cmd}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=capture_output,
            text=True,
            timeout=timeout,
            check=check,
            cwd=cwd,
            env=env,
            shell=shell,
        )
        return CommandResult(
            returncode=result.returncode,
            stdout=result.stdout if capture_output else "",
            stderr=result.stderr if capture_output else "",
        )
    except subprocess.TimeoutExpired:
        if is_verbose():
            logger.warning(f"Command timed out after {timeout}s: {cmd}")
        return CommandResult(
            returncode=-1,
            stdout="",
            stderr=f"Command timed out after {timeout} seconds",
            timed_out=True,
        )
    except subprocess.CalledProcessError as e:
        return CommandResult(
            returncode=e.returncode,
            stdout=e.stdout or "",
            stderr=e.stderr or "",
        )
    except FileNotFoundError as e:
        if is_verbose():
            logger.error(f"Command not found: {cmd[0] if isinstance(cmd, list) else cmd}")
        return CommandResult(
            returncode=127,
            stdout="",
            stderr=str(e),
        )


def run_with_timeout(
    cmd: Union[str, List[str]],
    timeout: int,
    **kwargs
) -> CommandResult:
    """
    Run a command with a specific timeout.

    Args:
        cmd: Command to run
        timeout: Timeout in seconds
        **kwargs: Additional arguments passed to run_command

    Returns:
        CommandResult
    """
    return run_command(cmd, timeout=timeout, **kwargs)


def check_tool_available(tool: str) -> bool:
    """
    Check if a tool is available in PATH.

    Args:
        tool: Tool name to check

    Returns:
        True if tool is available
    """
    return shutil.which(tool) is not None


def check_prerequisites(tools: List[str]) -> List[str]:
    """
    Check if required tools are available.

    Args:
        tools: List of tool names to check

    Returns:
        List of missing tools
    """
    missing = []
    for tool in tools:
        if not check_tool_available(tool):
            missing.append(tool)
    return missing

