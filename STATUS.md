# Evidence and known issues

| Capability | Last supported statement |
|---|---|
| Generated Guest C execution | Default execution architecture and linked dispatch verified in private builds |
| Manual Allied play | Earlier versions had user reports; not transferred to the latest Host |
| Three factions | Bounded stock scenario/House initialization observed; full faction content not comprehensively accepted |
| Campaign save/load | Specific Allied first-mission and sampled-state comparisons; not all missions or arbitrary midgame saves |
| Newest candidate | Release/Debug built, identities verified; fresh menu and ordinary exit pending |
| Isolated desktop failure | 0xC0000142; failing DLL remains unknown |
| Default-desktop initialization | Historical logs show Guest, graphics and audio initialization; menu/normal exit not proved |
| Native ABI harness in final takeover | Existing PowerShell script blocked before execution; historical results not counted as new |
| Temporal interpolation | Not implemented/accepted |
| Network parity | Fixture coverage is not real multiplayer acceptance |
| Ares/Phobos | Vendor LOAD, INIT, HOOK, LOGIC, GAMEPLAY and COMPATIBLE all pending |
| Fully standalone legal distribution | Not achieved |

The final takeover ran 151 focused Python tests with no failures or skips, while preserving prior full-suite evidence. It did not start a game or vendor DLL.

A historical player victory was reported and associated with a specific older session. That report does not prove the newest executable, universal AI correctness or deterministic multiplayer.

Known next research questions are retained for a future maintainer, not active work orders: normal startup diagnostics; typed callback context/pointer identity; precise internal Hook continuations; broader campaign persistence; exact rule parity; rights-cleared rebuildability.
