// The single wire protocol version shared by the Nuco client and relay.
// The relay rejects a connection whose MAJOR version does not match.

export interface ProtocolVersion {
  readonly major: number;
  readonly minor: number;
}

export const PROTOCOL_VERSION: ProtocolVersion = { major: 3, minor: 1 };

export const PROTOCOL_VERSION_STRING = `${PROTOCOL_VERSION.major}.${PROTOCOL_VERSION.minor}`;

// Two peers are compatible when their MAJOR versions match. A higher MINOR is
// treated as backward compatible: unknown optional fields are ignored.
export function isMajorCompatible(remote: ProtocolVersion): boolean {
  return Number.isInteger(remote.major) && remote.major === PROTOCOL_VERSION.major;
}
