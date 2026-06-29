# @nuco/protocol

The single source of truth for the Nuco client and relay wire protocol. The app
(`nuco-messenger`) and the relay (`nuco-server`) both depend on this package through a
local `file:../protocol` reference, so there is exactly one definition of every message,
error code, prekey shape, and the padding scheme.

Read `PROTOCOL.md` for the human readable spec. The typed implementation lives in `src/`.

## Scripts

- `npm run build`: compile to `dist/` (JS plus `.d.ts`). Runs automatically on install via
  the `prepare` hook, so consumers always get a built package.
- `npm run watch`: rebuild on change during development.
- `npm run typecheck`: type check without emitting.
- `npm run check`: drift and self test. Fails if `PROTOCOL.md` does not document every
  message type, error code, and the current version, or if the padding round trip breaks.

## Versioning

`PROTOCOL_VERSION` is `major.minor`. Bump the MAJOR for any breaking change; the relay
rejects mismatched majors. Bump the MINOR for backward compatible additions. Update
`PROTOCOL.md` in the same change so `npm run check` stays green.
