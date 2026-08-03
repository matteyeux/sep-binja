# SEP-binja

SEP firmware loader

### Description

Loads Apple SEP firmware, splitting it into individually addressed Mach-O modules.

Parses the Legion2 SEP firmware header, extracts every embedded Mach-O (boot stub, kernel, SEPOS root-server, all SEP apps, shared library), maps each one at a distinct 4 GiB-aligned virtual address range, creates properly typed sections, adds entry points, symbols, and optionally resolves shared-library GOT references. No external dependencies.

![](repo/demo1.png)


Also defined structs in the BinaryView.

![](repo/demo2.png)



### Headless analysis

`sep-analyze.py` loads a firmware, maps the modules you ask for and writes a
`.bndb` — no GUI, no clicking through the triage view for every image:

```bash
./sep-analyze.py --list sep-firmware.bin        # what is in it
./sep-analyze.py -m SEPOS -m SEPD sep-firmware.bin
./sep-analyze.py --all sep-firmware.bin -o sep-26.5.bndb
./sep-analyze.py sep-firmware.bin               # asks which modules
```

Run it with the interpreter Binary Ninja's API is installed in; it needs a
headless licence. Modules are mapped **before** the analysis runs, which is not
cosmetic: Binary Ninja analyzes a view once, and a SEP image starts empty, so
analyzing first leaves the modules with only what recursive descent reaches —
26896 functions against 31499 on the same 26-module image.

### Install

- MacOS: Copy to `~/Library/Application Support/Binary Ninja/plugins/` or use Plugin Manager
- Windows : Copy to `%APPDATA%\\Binary Ninja\\plugins` or use Plugin Manager
- Linux : Copy to `~/.binaryninja/plugins/` or use Plugin Manager



### Credits
- [plzdonthaxme](https://x.com/plzdonthaxme) for [sepsplit-rs](https://github.com/justtryingthingsout/sepsplit-rs) as this project is **heavily** inspired from his project
- [Proteas](https://x.com/ProteasWang) for the idea of [sep-fw-dyld-cache-loader](https://github.com/Proteas/sep-fw-dyld-cache-loader) as the objective of this project is to do the exact same thing but for Binja
