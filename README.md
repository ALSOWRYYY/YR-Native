# YR-Native — paused research archive

Active development was suspended indefinitely on 2026-11-14 at the owner's request.

This is a curated tools-and-documentation release candidate for a Yuri's Revenge static recompilation research project. It is **not the full engine source, a downloadable game, or a complete replacement for gamemd.exe**. The local development history, generated game code and private evidence are deliberately excluded pending rights review.

## What is preserved here

Generic storage accounting and preflight tools, their authored tests, selected independently written performance infrastructure if listed in RIGHTS_MANIFEST.json, and a factual record of the architecture, findings and limitations. The exact file list and hashes are in PUBLIC_SOURCE_SHA256.json.

## Research status at suspension

- Default experimental builds dispatched to Generated Guest C; a dispatch table had 24,939 entries. Fixed Guest addresses and native/shim services remained part of the runtime.
- Earlier versions had user-reported play, stock skirmish initialization and bounded campaign/save-load evidence. These are separate evidence categories, not comprehensive original-game parity.
- The newest candidate built in Release/Debug, but its main menu and normal exit were not verified. An isolated-desktop DLL initialization failure remained unresolved.
- A bounded dispatch index improved an offline production-macro benchmark. It does not establish a game FPS improvement.
- A corrected vendor inventory mapped 2,547 Hook declarations and 151 patches. Ares/Phobos binary execution, actual game effects and complete compatibility were not accepted.
- No new engine development or automatic game testing is requested.

## Use the public tools

Python 3.12 and its standard library are sufficient for the storage tools. Windows APIs provide actual allocated-space observations when available; denied or unavailable observations remain UNKNOWN. See [BUILDING.md](BUILDING.md) for exact offline tests and the limits of public rebuildability.

A full game build requires separately reviewed local engine/toolchain materials and files from a game copy the builder is legally entitled to use. This repository neither supplies those files nor grants rights to them. Ownership of a game copy alone is not a redistribution license.

Read [RIGHTS_SCOPE.md](RIGHTS_SCOPE.md), [ARCHITECTURE.md](ARCHITECTURE.md), [STATUS.md](STATUS.md), [HISTORY.md](HISTORY.md), [PERFORMANCE.md](PERFORMANCE.md) and [RECOVERY.md](RECOVERY.md).
Third-party status is version-specific; [THIRD_PARTY.md](THIRD_PARTY.md) must not be read as a general compatibility or legal certification.

## Maintenance

This archive is inactive. No response times, future features or compatibility commitments are promised. Contributions must identify authorship, license and evidence scope. Do not send commercial binaries, lifted game source, dumps, private mods or personal logs. See [CONTRIBUTING.md](CONTRIBUTING.md).

This candidate has not yet been published. Publication requires the owner's approval of the exact file list and rights report.
