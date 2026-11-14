# Performance evidence

The dispatch and callback timings below are offline authored fixtures. A separate Original-engine profile is described at the end; none proves YR-Native game FPS gains.

A 128-byte Guest-VA bucket index replaced repeated binary lookup in the existing dispatcher. The reviewed actual table had 24,939 entries, 31,719 buckets and requested 126,888 heap bytes; allocation was capped at 4 MiB. Invalid/sparse/allocation-failed candidates retain the original lookup. Atomic publication does not authorize concurrent initialization of the whole runtime.

21,163,189 comparisons produced no mismatches. Tests included full entries, neighboring/random/extreme addresses, allocation failures and concurrent index publication. Native/shim/override precedence and strict misses were tested through production call macros with authored bodies.

| Path | Old median ns | New median ns | Old p95 ns | New p95 ns |
|---|---:|---:|---:|---:|
| Random hit, production macro and authored body | 34.80770 | 14.39275 | 37.27480 | 15.64740 |
| Hot hit, same path | 29.33220 | 12.70760 | 32.09585 | 13.26245 |

MSVC x86 /O2, separate table translation unit, three independent process batches with seven repeats each: 21 timed samples of two million operations, interleaved runs, warm-up and raw QPC measurements. No empty-loop subtraction, best-only statistic, CPU affinity or priority manipulation. Percentiles describe batch means. Desktop load was uncontrolled.

A separate authored callback experiment compared unchanged NX/VEH dispatch with a direct entry into the same bridge. 144 paired contexts passed the tested GPR/EFLAGS/stack/x87/SSE/return checks. QPC medians: minimal UD2 4256.240 ns; production NX callback 4743.745 ns; direct authored entry 54.430 ns. Thread CPU quantization sometimes returned zero, not zero work.

The stock strict build does not install the old lift-in-native UD2 traps. Actual callback frequency is unknown. Pointer identity, reentry, exceptions, DF=1 and cross-thread behavior remain unproved, so the direct callback experiment was **not integrated**.

Earlier independent-presentation work measured bounded D3D11 test windows and source snapshots. It did not prove full visual interpolation, game speed-up or multiplayer determinism.

A separate late archival branch (4ac73d6, 547ffb3, 3d4d03d) preserved an owner-driven Original modified-game CPU profile: 120.716 seconds, 133,353 CPU events, zero reported loss. The main thread accounted for 88.219% of sampled events and DDRAW self time for 15.743%; 8.313% was in an unknown module and 61.533% was leaf-only. It had no matching PDB, GPU timing or measured FPS. This was the original modified executable, not YR-Native, so it cannot establish a Native speed-up or extension compatibility. Raw ETL, personal paths and mod data are private.
