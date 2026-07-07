# @nuco/protocol

The single source of truth for the Nuco client and relay wire protocol. Consumed by the
relay via `file:../protocol` and by the app via its committed `vendor/protocol` copy (so
EAS cloud builds, which upload only the app repo, can resolve it). See `../CLAUDE.md` for
the whole project picture and `PROTOCOL.md` for the human readable spec.

Rules:
- This is the ONLY definition of messages, error codes, prekey shapes, version, and padding.
  Change types and `PROTOCOL.md` together.
- Bump `PROTOCOL_VERSION` major for breaking changes (the relay rejects mismatched majors),
  minor for backward compatible additions.
- After any change run `npm run check` (it fails if `PROTOCOL.md` does not document every
  message type, error code, and the version, or if the padding round trip breaks), then
  `npm --prefix ../nuco-messenger run protocol:sync` and commit the refreshed
  `nuco-messenger/vendor/protocol` copy (the app depends on it so EAS builds work).
- No em dashes or en dashes. Commits look human authored (no AI attribution), conventional.
- `dist/` is gitignored; consumers build it via the `prepare` hook or `npm run build`.

Validators in `src/validate.ts` are the relay's untrusted input boundary; keep them strict
and dependency free.
