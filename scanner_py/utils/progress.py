"""Progress bar utilities for the scanner package."""

import sys
import time
from dataclasses import dataclass
from typing import Optional, List, Any
from contextlib import contextmanager


@dataclass
class ProgressStyle:
    """Style configuration for progress bars."""
    bar_char: str = "█"
    empty_char: str = "░"
    spinner_chars: str = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    width: int = 30
    show_percentage: bool = True
    show_count: bool = True
    show_eta: bool = False
    color_complete: str = "\033[92m"  # Green
    color_in_progress: str = "\033[94m"  # Blue
    color_failed: str = "\033[91m"  # Red
    color_reset: str = "\033[0m"


class ProgressBar:
    """
    A beautiful progress bar for terminal output.
    
    Supports:
    - Percentage display
    - Item counts
    - ETA estimation
    - Status icons
    - Color output
    """

    def __init__(
        self,
        total: int,
        description: str = "",
        style: Optional[ProgressStyle] = None,
        file: Any = None,
    ):
        """
        Initialize progress bar.

        Args:
            total: Total number of items
            description: Description text
            style: Style configuration
            file: Output file (default: stderr)
        """
        self.total = total
        self.description = description
        self.style = style or ProgressStyle()
        self.file = file or sys.stderr
        
        self.current = 0
        self.start_time = time.time()
        self.success_count = 0
        self.failed_count = 0
        self.skipped_count = 0
        self._last_line_length = 0

    def _is_tty(self) -> bool:
        """Check if output is a terminal."""
        return hasattr(self.file, 'isatty') and self.file.isatty()

    def _format_time(self, seconds: float) -> str:
        """Format seconds to human readable."""
        if seconds < 60:
            return f"{seconds:.0f}s"
        elif seconds < 3600:
            return f"{seconds / 60:.0f}m {seconds % 60:.0f}s"
        else:
            return f"{seconds / 3600:.0f}h {(seconds % 3600) / 60:.0f}m"

    def _get_eta(self) -> str:
        """Calculate estimated time remaining."""
        if self.current == 0:
            return "calculating..."
        
        elapsed = time.time() - self.start_time
        rate = self.current / elapsed
        remaining = (self.total - self.current) / rate if rate > 0 else 0
        return self._format_time(remaining)

    def _clear_line(self) -> None:
        """Clear the current line using ANSI escape codes."""
        if self._is_tty():
            # Use ANSI escape codes for reliable line clearing
            # \r - Move cursor to beginning of line
            # \033[K - Clear from cursor to end of line
            self.file.write("\r\033[K")
            self.file.flush()

    def update(
        self,
        n: int = 1,
        status: str = "success",
        current_item: str = "",
    ) -> None:
        """
        Update progress.

        Args:
            n: Number of items to increment
            status: Status of completed item (success/failed/skipped)
            current_item: Current item being processed
        """
        self.current += n
        
        if status == "success":
            self.success_count += 1
        elif status == "failed":
            self.failed_count += 1
        elif status == "skipped":
            self.skipped_count += 1

        self._render(current_item)

    def _render(self, current_item: str = "") -> None:
        """Render the progress bar."""
        # Calculate progress
        progress = self.current / self.total if self.total > 0 else 0
        filled = int(self.style.width * progress)
        empty = self.style.width - filled

        # Build bar
        if self._is_tty():
            bar = self.style.color_in_progress
            bar += self.style.bar_char * filled
            bar += self.style.color_reset
            bar += self.style.empty_char * empty
        else:
            bar = self.style.bar_char * filled + self.style.empty_char * empty

        # Build status counts
        counts = []
        if self.success_count > 0:
            if self._is_tty():
                counts.append(f"\033[92m✓{self.success_count}\033[0m")
            else:
                counts.append(f"✓{self.success_count}")
        if self.failed_count > 0:
            if self._is_tty():
                counts.append(f"\033[91m✗{self.failed_count}\033[0m")
            else:
                counts.append(f"✗{self.failed_count}")
        if self.skipped_count > 0:
            if self._is_tty():
                counts.append(f"\033[93m🚫{self.skipped_count}\033[0m")
            else:
                counts.append(f"🚫{self.skipped_count}")
        
        status_str = " ".join(counts)

        # Build line
        parts = []
        if self.description:
            parts.append(self.description)
        
        parts.append(f"[{bar}]")
        
        if self.style.show_percentage:
            parts.append(f"{progress * 100:5.1f}%")
        
        if self.style.show_count:
            parts.append(f"({self.current}/{self.total})")
        
        if status_str:
            parts.append(status_str)

        # Truncate current item if needed
        if current_item:
            max_item_len = 30
            if len(current_item) > max_item_len:
                current_item = "..." + current_item[-(max_item_len - 3):]
            parts.append(current_item)

        line = " ".join(parts)
        
        # Clear and print using ANSI escape codes
        self._clear_line()
        
        if self._is_tty():
            # \r moves to beginning, line already cleared by _clear_line
            self.file.write(f"\r{line}")
        else:
            self.file.write(f"{line}\n")
        
        self.file.flush()
        self._last_line_length = len(line) + 10  # Extra padding for ANSI codes

    def finish(self, message: str = "") -> None:
        """
        Finish the progress bar.

        Args:
            message: Final message to display
        """
        self._clear_line()
        
        # Final status
        elapsed = time.time() - self.start_time
        elapsed_str = self._format_time(elapsed)
        
        parts = []
        if self.description:
            parts.append(self.description)
        
        # Final icon
        if self.failed_count == 0:
            parts.append("✅")
        else:
            parts.append("⚠️")
        
        parts.append(f"Completed {self.current}/{self.total}")
        
        if self.success_count > 0:
            parts.append(f"({self.success_count} ✓")
            if self.failed_count > 0:
                parts.append(f", {self.failed_count} ✗")
            if self.skipped_count > 0:
                parts.append(f", {self.skipped_count} 🚫")
            parts[-1] += ")"
        
        parts.append(f"in {elapsed_str}")
        
        if message:
            parts.append(f"- {message}")
        
        line = " ".join(parts)
        self.file.write(f"{line}\n")
        self.file.flush()


class Spinner:
    """A spinner for indeterminate progress."""

    def __init__(
        self,
        message: str = "Processing...",
        style: Optional[ProgressStyle] = None,
        file: Any = None,
    ):
        """
        Initialize spinner.

        Args:
            message: Message to display
            style: Style configuration
            file: Output file
        """
        self.message = message
        self.style = style or ProgressStyle()
        self.file = file or sys.stderr
        self._frame = 0
        self._running = False

    def _is_tty(self) -> bool:
        """Check if output is a terminal."""
        return hasattr(self.file, 'isatty') and self.file.isatty()

    def spin(self) -> None:
        """Advance spinner by one frame."""
        if not self._is_tty():
            return
            
        char = self.style.spinner_chars[self._frame % len(self.style.spinner_chars)]
        # Use ANSI escape codes to clear line and write
        self.file.write(f"\r\033[K{char} {self.message}")
        self.file.flush()
        self._frame += 1

    def update(self, message: str) -> None:
        """Update the spinner message."""
        self.message = message
        self.spin()

    def finish(self, message: str = "", success: bool = True) -> None:
        """Finish the spinner."""
        if self._is_tty():
            # Use ANSI escape codes to clear the line
            self.file.write("\r\033[K")
        
        icon = "✅" if success else "❌"
        final_msg = message or self.message
        self.file.write(f"{icon} {final_msg}\n")
        self.file.flush()


@contextmanager
def progress_context(
    total: int,
    description: str = "",
    style: Optional[ProgressStyle] = None,
):
    """
    Context manager for progress bar.

    Usage:
        with progress_context(100, "Scanning") as progress:
            for item in items:
                process(item)
                progress.update()
    """
    progress = ProgressBar(total, description, style)
    try:
        yield progress
    finally:
        progress.finish()


class MultiProgress:
    """
    Track progress for multiple parallel tasks.
    
    Each task shows individual progress while maintaining
    an overall view.
    """

    def __init__(
        self,
        tasks: List[str],
        description: str = "",
        style: Optional[ProgressStyle] = None,
        file: Any = None,
    ):
        """
        Initialize multi-progress tracker.

        Args:
            tasks: List of task names
            description: Overall description
            style: Style configuration
            file: Output file
        """
        self.tasks = tasks
        self.description = description
        self.style = style or ProgressStyle()
        self.file = file or sys.stderr
        
        self.total = len(tasks)
        self.completed = 0
        self.results: dict = {}
        self.start_time = time.time()

    def complete_task(
        self,
        task: str,
        status: str = "success",
    ) -> None:
        """
        Mark a task as complete.

        Args:
            task: Task name
            status: Completion status
        """
        self.results[task] = status
        self.completed += 1
        self._render()

    def _render(self) -> None:
        """Render progress."""
        progress = self.completed / self.total if self.total > 0 else 0
        
        success = sum(1 for s in self.results.values() if s == "success")
        failed = sum(1 for s in self.results.values() if s == "failed")
        skipped = sum(1 for s in self.results.values() if s == "skipped")
        
        # Build status string
        parts = []
        if self.description:
            parts.append(self.description)
        
        parts.append(f"[{self.completed}/{self.total}]")
        parts.append(f"{progress * 100:.0f}%")
        
        if success > 0:
            parts.append(f"✓{success}")
        if failed > 0:
            parts.append(f"✗{failed}")
        if skipped > 0:
            parts.append(f"🚫{skipped}")
        
        line = " ".join(parts)
        
        if hasattr(self.file, 'isatty') and self.file.isatty():
            self.file.write(f"\r{line}" + " " * 20)
        else:
            self.file.write(f"{line}\n")
        
        self.file.flush()

    def finish(self) -> None:
        """Finish and show summary."""
        elapsed = time.time() - self.start_time
        
        success = sum(1 for s in self.results.values() if s == "success")
        failed = sum(1 for s in self.results.values() if s == "failed")
        skipped = sum(1 for s in self.results.values() if s == "skipped")
        
        # Clear line
        if hasattr(self.file, 'isatty') and self.file.isatty():
            self.file.write("\r" + " " * 80 + "\r")
        
        icon = "✅" if failed == 0 else "⚠️"
        self.file.write(
            f"{icon} {self.description} completed: "
            f"{success} successful, {failed} failed, {skipped} skipped "
            f"({elapsed:.1f}s)\n"
        )
        self.file.flush()

