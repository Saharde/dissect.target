from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.plugins.os.unix.linux.proc import ProcPlugin
from dissect.target.plugins.os.unix.linux.procmaps import ProcmapsPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


PROC_MAPS = """00400000-00401000 r-xp 00000000 08:01 12345 /usr/bin/testproc
00600000-00601000 rw-p 00000000 08:01 12345 /usr/bin/testproc
"""

def test_modules_plugin(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    fs_unix.map_file("/proc/1234/maps", absolute_path("_data/plugins/os/unix/linux/procmaps/123_proc_maps"))

    target_unix.filesystems.add(fs_unix)

    target_unix.add_plugin(ProcPlugin)
    target_unix.add_plugin(ProcmapsPlugin)
    
    results = list(target_unix.procmaps())
    assert len(results) == 1

    r = results[0]

    assert r.pid == 1234
    assert r.name == "testproc" or r.name is not None
    assert r.start_addr == 0x00400000
    assert r.end_addr == 0x00401000
    assert r.perms == "r-xp"
    assert r.offset == 0
    assert r.dev == "08:01"
    assert r.inode == 12345
    assert r.pathname == "/usr/bin/testproc" or r.pathname is not None