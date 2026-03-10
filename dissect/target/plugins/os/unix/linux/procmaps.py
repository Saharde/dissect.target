from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

ProcmapsRecord = TargetRecordDescriptor(
    "linux/proc/procmaps",
    [
        ("datetime", "ts"),
        ("string", "name"),
        ("varint", "pid"),
        ("varint", "start_addr"),
        ("varint", "end_addr"),
        ("string", "perms"),
        ("varint", "offset"),
        ("string", "dev"),
        ("varint", "inode"),
        ("string", "pathname"),
    ],
)


class ProcmapsPlugin(Plugin):
    """Linux volatile proc environment plugin."""

    def check_compatible(self) -> None:
        if not self.target.has_function("proc"):
            raise UnsupportedPluginError("proc filesystem not available")

    @export(record=ProcmapsRecord)
    def procmaps(self) -> Iterator[ProcmapsRecord]:
        """Return the memory maps for all processes.

        Yields TargetRecordDescriptor with the following fields:

        .. code-block:: text

            ts (datetime): The modification timestamp of the processes' maps file.
            name (string): The name associated to the pid.
            pid (varint): The process id (pid) of the process.
            start_addr (varint): The start vaddr of the map.
            end_addr (varint): The End vaddr of the map.
            perms (string): The permission of the memory map.
            offset (varint): The offset the mappings from (the offset into the file/etc).
            dev (string): The device associated with the map.
            inode: The inode in the device (the inode of the file).
            pathname: The name of the mapped region (filepath/vdso/heap/stack..).
        """
        pass
