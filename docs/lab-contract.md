**Tenant export test laboratory**

This fixture is independent of the harness implementation language. All identities, tokens, and data are synthetic and public within the project.

The first lab provides vulnerable and patched variants of the same export service. Both require a valid bearer token. The vulnerable variant omits the ownership check when retrieving an export; the patched variant checks the authenticated identity's tenant against the export owner.

| Request | Vulnerable | Patched |
|---|---|---|
| Tenant A reads export A | 200, exact A fixture | 200, exact A fixture |
| Tenant B reads export B | 200, exact B fixture | 200, exact B fixture |
| Tenant A reads export B | 200, exact B fixture | 404, no export content |
| Tenant B reads export A | 200, exact A fixture | 404, no export content |
| Missing or invalid token | 401 | 401 |
| Valid identity reads nonexistent export | 404 | 404 |

The normal controls must pass before a cross-tenant observation is treated as evidence. Check returned resource content and ownership, not only HTTP status. A fresh lab instance restores the fixed dataset; requests in this milestone do not mutate fixtures.

Run local lab servers on loopback. Keep the variant explicit at startup, default to patched, and expose variant/fixture metadata for reproducible tests. This laboratory is a test target, not an implementation of the eventual scanning service.
