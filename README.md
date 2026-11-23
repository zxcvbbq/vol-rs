# vol-rs

A port of the Volatility 3 memory forensics framework from Python to Rust. It reads the same memory images, runs the same plugins with the same options, and prints the same output, byte for byte, a good deal faster.

This is [**zxcvbbq**'s fork](https://github.com/zxcvbbq/vol-rs) of [daffainfo/vol-rs](https://github.com/daffainfo/vol-rs). It tracks upstream Volatility 3 through **2.28.3** and carries fixes for kernels and Windows builds that the port did not yet handle. See [What this fork adds](#what-this-fork-adds).

## What this fork adds

The port was matched against Volatility **2.28.0**. Upstream has since moved to 2.28.3, and several of those changes were fixes for images this port could not analyse correctly. Each one below was ported from the upstream source rather than guessed at.

### Linux

| Change | Effect |
|---|---|
| Boot time from `timekeeper_data` (6.17+) | `tk_core` became a macro over `timekeeper_data[TIMEKEEPER_CORE]`. Without this, every task timestamp on a 6.17+ kernel was wrong or unavailable. |
| `page.__folio_index` | A 2025 folio change renamed `page.index`. Cached-page indexes read as zero, so file recovery laid pages out at the wrong offsets. |
| `memdesc_flags_t` | Page `flags` are now wrapped in a struct with the bits in `.f`. Flags read as blank. |
| `kernel_cap_t` before 6.3 | Before 6.3 `kernel_cap_t` is a typedef of the older two-word structure. The port raised `Unsupported kernel capabilities implementation`; both layouts are now read. |
| Taint table | `RANDSTRUCT` is no longer a per-module flag, `FWCTL` and the `G` letter were missing, and letters the table does not know are now named `<UNKNOWN_TAINT_CHAR_x>` instead of being dropped silently. |
| `linux.malfind` | Rewritten to upstream's current algorithm: `--dump-regions` with a `File output` column, `--show-all-dirty-pages`, `--hexdump-size` and `--dump-maxsize`, and per-address page sizing so large pages are not re-walked once per 4 KiB. |

### Windows

| Change | Effect |
|---|---|
| Contiguous DTB search range | The fast path was three ranges with two gaps. A Windows 11 25H2 System DTB at `0x7b5000` fell inside a gap, which made **every** plugin fail on that image. |
| Kernel base attribution | Scanning from `hal.dll`'s header reached the PDB of the ntoskrnl above it and used hal's address as the kernel base, shifting every symbol by `0x48000` and leaving `pslist` empty. A record now only counts when its own image starts at the address being checked. |
| `scheduled_tasks` architecture | The requirement listed `Intel33` instead of `Intel32`, so the plugin could never run on a 32-bit image. |

### Verified

- **197 of 197 plugin help pages are byte-identical to Volatility 2.28.3**, including the nine plugins that changed above.
- 169 unit tests pass, 13 of them new and covering the kernel-base attribution bug, both page layouts, and the taint semantics.
- The Linux and Windows fixes were written from the upstream diffs and checked against upstream's own behaviour where it could be exercised locally.

There are no memory captures on the machine this fork was prepared on, so the tables below are the original author's measurements, not re-run here. The fixes above are verified at the source and unit-test level rather than against fresh captures. That is the honest state of it, and the [To do](#to-do) list is where to push next.

## License

This project is a port of Volatility 3 and is therefore an "Addition" under the Volatility Software License 1.0, so it is published under that same license. The full text is in [LICENSE](LICENSE) and online at https://www.volatilityfoundation.org/license/vsl-v1.0. Every source file keeps the notice recording what it was derived from.

This project is not affiliated with or endorsed by the Volatility Foundation. The name Volatility is used only to say what this is a port of.

## Building

Rust 1.85 or newer, then:

```
cargo build --release
```

The binary lands at `target/release/vol-rs`. Nothing optional is needed. Symbol decompression, RC4, DES, AES, YARA matching, PNG writing and tar archives are all built in, where the Python version reaches for `pycryptodomex`, `yara-python` and `pillow`. Instructions are decoded by capstone 5.0.6, the same library the Python version uses for the same columns, compiled in rather than installed alongside.

## Using it

```
./target/release/vol-rs -f memory.raw windows.pslist.PsList
./target/release/vol-rs -f memory.lime linux.bash.Bash
./target/release/vol-rs -f memory.raw -r csv windows.netscan.NetScan
./target/release/vol-rs windows.malfind.Malfind --help
./target/release/vol-rs --list-plugins
```

Every option the Python version takes is taken here too, with the same names and the same defaults, including `-o`, `-r`, `-s`, `-c`, `-e`, `--filters`, `--hide-columns`, `--save-config`, `--stackers` and `--single-swap-locations`. Each plugin's own options match as well, which the help pages show: all 197 of them are identical to the Python ones, character for character.

### New in this fork

```
# Dump the suspicious region for each hit, not just its first 64 bytes.
./target/release/vol-rs -f memory.lime linux.malfind.Malfind --dump-regions

# Report every dirtied page in an executable mapping, not just the first.
./target/release/vol-rs -f memory.lime linux.malfind.Malfind --show-all-dirty-pages

# Show more of each region.
./target/release/vol-rs -f memory.lime linux.malfind.Malfind --hexdump-size 256
```

## Symbols

Symbol packs go in `$XDG_DATA_HOME/vol-rs/symbols`, or `~/.local/share/vol-rs/symbols` when that variable is not set. A pack somewhere else is named with `--symbol-dirs` or through the `VOLRS_SYMBOL_PATH` environment variable. A Windows kernel that no pack describes is looked up on the Microsoft symbol server, and the database found there is turned into a symbol file and kept, so the fetch happens once. The database itself is cached under `~/.cache/vol-rs` and the symbol file is written beside the packs.

## What has been checked

These are the original author's measurements against Volatility 2.28.0. Both sides were run against the same captures and diffed, header framing and trailing newlines included:

| Capture | Plugins run | Identical |
|---|---:|---:|
| Windows 11 24H2, build 26100, 4.3 GB crash dump | 113 | 105 |
| Ubuntu 22.04, kernel 6.5.0-41, 4.3 GB VMware snapshot | 69 | 61 |
| Windows 10 19041, 2.0 GB crash dump | 114 | 112 |
| Windows XP, 512 MB raw capture | 114 | 113 |
| Linux 3.2, 512 MB raw capture | 60 | 60 |

The eight plugins that take a pattern or a rule were given one, the same on both sides, rather than left out. Three of the differences found that way were defects in the port and are fixed.

| Other check | Result |
|---|---|
| Files written by extracting plugins | 24,441 compared, every one equal |
| Plugin help pages | 197 of 197 identical against 2.28.3 (re-checked for this fork) |
| Renderers | `csv`, `json`, `jsonl`, `quick` and `pretty` compared on several plugins, all identical |

Instructions are decoded by the same library the Python version uses, compiled in at version 5.0.6, which is the version the reference was pinned to for these comparisons. Version 5.0.7 decodes one more instruction form, which changes how about two percent of `windows.mbrscan`'s lines are spelled on the Windows 10 capture and nothing else.

Windows symbols for the captures used here come from the symbol packs the Volatility Foundation publishes, read by both tools, except the Windows 11 24H2 kernel, which no pack describes and whose description is built from the database Microsoft publishes. For an earlier Windows 10 19045 capture the description this port builds that way matched the one the Python version builds from the same database exactly, across all 16 base types, 293 enumerations, 1,653 structures and 40,007 symbols.

## Speed

The ten widest gaps on each capture. Every figure, and every plugin compared, is in [BENCHMARKS.md](BENCHMARKS.md).

### Windows 11 24H2 crash dump, 4.3 GB

| Plugin | Rust | Python | Faster |
|---|---:|---:|---:|
| `windows.malfind.Malfind` | 0.494 s | 392 s | x793 |
| `windows.malware.suspicious_threads.SuspiciousThreads` | 0.621 s | 488 s | x786 |
| `windows.malware.malfind.Malfind` | 0.569 s | 393 s | x691 |
| `windows.suspicious_threads.SuspiciousThreads` | 0.739 s | 461 s | x624 |
| `windows.hollowprocesses.HollowProcesses` | 0.646 s | 326 s | x504 |
| `windows.malware.hollowprocesses.HollowProcesses` | 0.661 s | 322 s | x487 |
| `layerwriter.LayerWriter` | 0.044 s | 17.4 s | x395 |
| `configwriter.ConfigWriter` | 0.046 s | 16.7 s | x363 |
| `windows.vadinfo.VadInfo` | 1.36 s | 488 s | x358 |
| `windows.verinfo.VerInfo` | 0.541 s | 159 s | x294 |

### Ubuntu 22.04 VMware snapshot, 4.3 GB

| Plugin | Rust | Python | Faster |
|---|---:|---:|---:|
| `linux.sockstat.Sockstat` | 6.36 s | 2030 s | x319 |
| `timeliner.Timeliner` | 9.56 s | 1070 s | x112 |
| `linux.lsmod.Lsmod` | 0.282 s | 29.0 s | x103 |
| `linux.psscan.PsScan` | 1.09 s | 111 s | x102 |
| `linux.mountinfo.MountInfo` | 0.697 s | 70.3 s | x101 |
| `yarascan.YaraScan` | 0.909 s | 79.6 s | x88 |
| `linux.malware.netfilter.Netfilter` | 0.6 s | 49.9 s | x83 |
| `linux.ptrace.Ptrace` | 0.253 s | 20.4 s | x81 |
| `linux.pstree.PsTree` | 0.213 s | 16.2 s | x76 |
| `linux.ip.Link` | 0.22 s | 16.4 s | x74 |

### Windows 10 19041 crash dump, 2.0 GB

| Plugin | Rust | Python | Faster |
|---|---:|---:|---:|
| `windows.malware.suspicious_threads.SuspiciousThreads` | 0.677 s | 346 s | x511 |
| `windows.suspicious_threads.SuspiciousThreads` | 0.677 s | 343 s | x507 |
| `windows.malfind.Malfind` | 0.734 s | 320 s | x436 |
| `windows.hollowprocesses.HollowProcesses` | 0.565 s | 244 s | x432 |
| `windows.malware.malfind.Malfind` | 0.73 s | 313 s | x429 |
| `windows.vadinfo.VadInfo` | 0.983 s | 412 s | x419 |
| `windows.malware.hollowprocesses.HollowProcesses` | 0.648 s | 240 s | x370 |
| `configwriter.ConfigWriter` | 0.043 s | 14.5 s | x337 |
| `layerwriter.LayerWriter` | 0.039 s | 11.9 s | x304 |
| `windows.registry.hivelist.HiveList` | 0.038 s | 7.54 s | x198 |

### Windows XP raw capture, 512 MB

| Plugin | Rust | Python | Faster |
|---|---:|---:|---:|
| `windows.suspicious_threads.SuspiciousThreads` | 0.184 s | 34.5 s | x188 |
| `windows.malware.suspicious_threads.SuspiciousThreads` | 0.2 s | 33.2 s | x166 |
| `windows.malware.hollowprocesses.HollowProcesses` | 0.209 s | 31.0 s | x148 |
| `windows.vadinfo.VadInfo` | 0.263 s | 38.5 s | x146 |
| `windows.hollowprocesses.HollowProcesses` | 0.207 s | 28.1 s | x136 |
| `windows.mftscan.ResidentData` | 0.205 s | 27.6 s | x135 |
| `windows.malfind.Malfind` | 0.203 s | 26.3 s | x130 |
| `windows.mftscan.MFTScan` | 0.393 s | 48.2 s | x123 |
| `windows.malware.malfind.Malfind` | 0.24 s | 28.2 s | x118 |
| `windows.verinfo.VerInfo` | 0.215 s | 25.1 s | x117 |

### Linux 3.2 raw capture, 512 MB

| Plugin | Rust | Python | Faster |
|---|---:|---:|---:|
| `linux.library_list.LibraryList` | 0.525 s | 917 s | x1747 |
| `linux.pscallstack.PsCallStack` | 0.31 s | 98.8 s | x319 |
| `linux.lsmod.Lsmod` | 0.059 s | 9.58 s | x162 |
| `linux.malware.check_idt.Check_idt` | 0.11 s | 15.2 s | x138 |
| `linux.check_idt.Check_idt` | 0.115 s | 15.1 s | x131 |
| `linux.tty_check.tty_check` | 0.114 s | 14.3 s | x125 |
| `linux.malware.tty_check.Tty_Check` | 0.129 s | 15.0 s | x116 |
| `linux.malware.check_modules.Check_modules` | 0.055 s | 5.74 s | x104 |
| `linux.kallsyms.Kallsyms` | 0.278 s | 28.9 s | x104 |
| `linux.capabilities.Capabilities` | 0.056 s | 5.82 s | x104 |

## Known differences

These are deliberate, and will not change:

* `--save-config` and `timeliner --record-config` record every setting that describes the image, but not the Python version's checks that an imported component is new enough, because this port has no such checks to record.
* `frameworkinfo` and `isfinfo` describe the tool rather than the image, so they report this port's own layers, plugins and symbol files.
* The line in `--help` naming the cache directory names this port's own cache.
* `windows.callbacks` leaves out the shutdown notifications it cannot parse. On a 64-bit image the Python version runs no check on them at all, so it reports two entries on the Windows 11 capture that are ntoskrnl's own instruction bytes rather than callbacks, marked as unparsed.

## Not reproducible

Nothing here can match, because the output is not the same twice even from one tool:

* `linux.pagecache.RecoverFs` stamps every file in the tarball it writes with the moment the plugin ran, so no two runs agree, not even two Python runs. The table matches and so does the unpacked tree.
* `linux.mountinfo --mount-format` joins a Python set, so its column order changes between two Python runs. This port lists the mount options first and the filesystem options after, in the order the kernel holds them.
* `timeliner` with no filter appends the timeline again after every plugin, and the order the plugins run in is the order `os.walk` returned the plugin directory, which is a property of the install rather than of the release. Two Python installs of the same version report different totals on the same image. This port runs a fixed list, the order a stock install on ext4 produces.
* `windows.memmap.Memmap` on the larger captures is killed by the out of memory killer part way through, and where it stops depends on the free memory at the time, so two Python runs do not agree with each other either. On the Windows XP capture both finish and the output matches.

## Where the Python version stops first

These differ because the Python version ends early and this port does not. Every line the Python version wrote before stopping is reproduced exactly, and the rest is what it did not reach:

| Plugin | What happens |
|---|---|
| `windows.hashdump`, `windows.cachedump`, `windows.lsadump` | the Python version raises on a hive page that is not resident, where this port reports what it could read and carries on |
| `linux.kallsyms` | `TypeError: pointer_to_string takes a Pointer` after 196,399 of 208,258 rows |
| `linux.kmsg`, `linux.hidden_modules` | `AttributeError: 'NativeTable' object has no attribute 'producer'` before the first row |
| `linux.pagecache.RecoverFs` | `AttributeError: StructType has no attribute: page.mapping` after 3,639 of 34,625 rows on the Ubuntu capture |
| `linux.library_list`, `linux.pscallstack` | still running after 45 minutes, where this port finishes in seconds |

`isfinfo` is in neither list. Without `--live` the Python version lists its own identifier database in that database's order, where this port lists the symbol directories, so neither answer is derivable from the other.

## To do

Everything below is ported and builds, but has not been run against real evidence yet:

- [ ] Run the 2.28.3 fixes against real captures. The 6.17+ boot time, the folio page index and flags, pre-6.3 capabilities, the Windows 11 25H2 DTB range and the kernel-base attribution fix are all verified at source level and by unit test, but no image exercising them has been through this fork yet. This is the first thing to do.
- [ ] Test the 23 macOS plugins against a real Mac capture. All 23 were read line by line against the Python source, and every type, member and symbol they touch was checked against the 129 published Darwin symbol files covering 10.6 to 10.15, so the version fallbacks are known to be complete. What is left is a real Mac image to run them on.
- [ ] Test the remaining image formats. Raw, VMware, LiME and Windows crash dump captures have all been used, so the AVML, QEMU, ELF core and Xen layers are the ones still unproven on real files.
- [ ] Test more kernel versions. Windows XP, Windows 10 19041 and 19045, Windows 11 24H2, Linux 3.2, Ubuntu 22.04 on 6.5 and Linux 6.8 is still a narrow base, and plugins that read version specific structures are where a port is most likely to drift.
- [ ] Add the arrow and parquet renderers. They are accepted on the command line and refused, which is what the Python version does when its table library is missing.

## Credit

Volatility 3 is the work of the Volatility Foundation and its contributors. The Rust port is [daffainfo](https://github.com/daffainfo/vol-rs)'s. This fork carries upstream 2.28.3 fixes forward onto that port; it is their design, their plugin set and their output format throughout, and it exists because that work is open.
