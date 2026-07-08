// Stable machine error codes. The relay never sends human readable text. The app
// maps each code to a localized string (see the app i18n error namespace).

export enum ErrorCode {
  ProtocolVersionMismatch = 'PROTOCOL_VERSION_MISMATCH',
  MalformedMessage = 'MALFORMED_MESSAGE',
  Unauthenticated = 'UNAUTHENTICATED',
  AuthFailed = 'AUTH_FAILED',
  NotRegistered = 'NOT_REGISTERED',
  NoSuchHandle = 'NO_SUCH_HANDLE',
  RateLimited = 'RATE_LIMITED',
  AttestationRequired = 'ATTESTATION_REQUIRED',
  AttestationFailed = 'ATTESTATION_FAILED',
  QueueFull = 'QUEUE_FULL',
  MessageTooLarge = 'MESSAGE_TOO_LARGE',
  CallsUnavailable = 'CALLS_UNAVAILABLE',
  Internal = 'INTERNAL',
}

// The string union form, handy for typing wire payloads.
export type ErrorCodeValue = `${ErrorCode}`;

export const ALL_ERROR_CODES: readonly ErrorCodeValue[] = Object.values(ErrorCode);
