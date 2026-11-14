# Architecture at suspension

The private engine pipeline was: user-owned supported x86 game input → input-bound analysis and generation → Generated C plus Host/runtime → Windows x86 executable.

The execution model preserved 32-bit Guest virtual-address identity, global data, object layouts, function pointers and callback conventions. Generated C functions lived at Host addresses; Guest addresses were not interchangeable with Host RVAs. A dispatch table resolved guest function identities. Windows services and selected external libraries were provided through native and shim boundaries.

The default strict stock build isolated original code-page execution. An explicit historical Original mode existed for reference work. Neither fact alone measures dynamic execution coverage or proves complete independence from original data. Private derived initialization data, source metadata and legally provided resources still mattered.

Simulation timing and presentation had been separated experimentally. High refresh presentation is not the same as independent new animation frames. Full temporal interpolation and deterministic parallel simulation were not proved.

Manual play followed the original window-input path. Programmatic input used distinct source identity, freshness, one-time claim and Native admission boundaries. These protections were not a replacement for normal human input.

Reports separated command acknowledgment, observed game consequence, object lifetime, visuals and tests. P5–P8 WORLD domains were bounded diagnostic protocols, not game object limits.

A legacy vendor byte patch at an original Guest VA does not automatically modify the Generated C body that actually executes. Internal Hook sites require exact local-register/flags/stack/FPU state and legal continuation, not just a function-entry override. The corrected inventory is research groundwork, not an execution bridge.

Only the independently reviewed public subset appears here. Source reconstruction or interoperability permission is not inferred from this architecture description.
