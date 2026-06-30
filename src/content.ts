// The decrypted plaintext payload carried inside a sealed MessageEnvelope. The relay never
// sees this: it is end to end encrypted, padded, then sealed. Wrapping every message in a
// typed content envelope lets peers carry control messages (disappearing message requests)
// on the same channel as ordinary text, without the relay learning anything new.
//
// This is part of the wire contract between two peers (not between client and relay), so it
// lives here in @nuco/protocol. Adding a content variant is a backward compatible (minor)
// change: a peer that does not understand a variant falls back to treating it as text.

// TextEncoder/TextDecoder are standard globals on both runtimes we target (Node and Hermes),
// but the package lib is pure ES2022 (no DOM, no Node) to stay dependency free, so declare the
// minimal surface we use. The real global is used at runtime.
interface TextEncoderLike {
  encode(input: string): Uint8Array;
}
interface TextDecoderLike {
  decode(input?: Uint8Array): string;
}
declare const TextEncoder: { new (): TextEncoderLike };
declare const TextDecoder: { new (label?: string): TextDecoderLike };

const encoder = new TextEncoder();
const decoder = new TextDecoder(); // utf-8

export type MessageContent =
  | { readonly t: 'text'; readonly body: string }
  | { readonly t: 'retention/request'; readonly value: number } // requested retention, seconds (0 = off)
  | { readonly t: 'retention/accept'; readonly value: number } // accept a pending request of `value`
  | { readonly t: 'retention/cancel' }; // requester cancels, or recipient declines, a pending request

export type MessageContentType = MessageContent['t'];

// Force exhaustiveness: adding a variant without listing it here is a type error.
const MESSAGE_CONTENT_TYPE_MAP: Record<MessageContentType, true> = {
  text: true,
  'retention/request': true,
  'retention/accept': true,
  'retention/cancel': true,
};

export const MESSAGE_CONTENT_TYPES = Object.keys(MESSAGE_CONTENT_TYPE_MAP) as MessageContentType[];

export function encodeContent(content: MessageContent): Uint8Array {
  return encoder.encode(JSON.stringify(content));
}

// Decode bytes into a typed content. Tolerant by design: anything that is not a recognized
// content object is treated as a raw text body, so a peer sending plain text (or a future
// unknown variant) still renders as a message rather than being dropped.
export function decodeContent(bytes: Uint8Array): MessageContent {
  const text = decoder.decode(bytes);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { t: 'text', body: text };
  }
  if (isMessageContent(parsed)) return parsed;
  return { t: 'text', body: text };
}

function isMessageContent(v: unknown): v is MessageContent {
  if (typeof v !== 'object' || v === null) return false;
  const o = v as Record<string, unknown>;
  switch (o.t) {
    case 'text':
      return typeof o.body === 'string';
    case 'retention/request':
    case 'retention/accept':
      return typeof o.value === 'number' && Number.isFinite(o.value) && o.value >= 0;
    case 'retention/cancel':
      return true;
    default:
      return false;
  }
}
