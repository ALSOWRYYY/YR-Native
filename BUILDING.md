# Building and testing

## This public subset

Install Python 3.12. From this repository root run:

    python -B -m unittest tools.tests.test_storage_budget tools.tests.test_storage_audit

These tests use authored temporary data. They do not start the game, generate game C or test gameplay. Full allocated-space reporting uses Windows filesystem APIs; platforms unable to provide it must retain UNKNOWN rather than report logical size as allocated space.

Review tool arguments before use. The audit is read-only. The budget tool has an explicitly opted-in subprocess mode: a disk preflight is not authorization to run arbitrary commands.

## Private game build record — not a runnable public recipe

The frozen engine build used MSVC x86 19.51.36248.0, CMake/Ninja, Python 3.12.14 and fixed pcrecomp/runtime sources. Engine runtime checkpoint: b8d352513852d7fd6a75b8b45f91f794b2b95dcc; toolkit: 2029742ac4c40ecf94bdaaf8e1b5e30c5ae57cc9. Final local integration including tools/docs: 7611b43a9a1790eb6d3e099c6ca202a6689ef78b.

The supported input was pinned by SHA-256:
3e81a61775d2745d1dabe397325ef663cd994ffc194da4e998e3bf5d2d308600.
Do not download or redistribute it through this project. Exact input identity does not grant rights.

The private build flow verifies the input and analysis pins, regenerates or verifies 67 generated files, selects target gamemd, compiles Release or Debug with a fixed toolchain, and issues fresh object seals/link tickets. Each configuration includes 96 identified objects. PDB GUID/age must match that exact EXE. Changing a link requires a new identity record.

The full engine, analysis, generated files and private runtime data are withheld. **Cloning this public subset cannot build gamemd.exe.** No fake build stub is supplied. Future publication of more source requires file-by-file rights review and a clean rebuild demonstration.

## Research header boundary

research/dispatch_index.h is not an independent executable or a complete Native32 runtime. Its including MSVC x86 translation unit must provide Win32 declarations, stdint/size_t, recomp_func_t, an immutable sorted recomp_dispatch_table and recomp_dispatch_count. No game table or runnable public benchmark is distributed. The public Python tests do not compile or validate this C header. Earlier private benchmark results are documented separately.
