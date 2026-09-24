/**
 * "Is this AWS response the whole answer?" — the pure detection half of
 * AWS pagination, split into its own module so the AWS call layer can use it.
 *
 * awsApi.ts needs these to notice an unread continuation token, and
 * pagination.ts needs them to drive a walk. Putting them there and here would
 * be a cycle (pagination imports the call helpers from awsApi), and a cycle in
 * a load-bearing path is not worth the byte it saves. This module depends on
 * nothing but the flat-XML field reader, so both can import it freely.
 */
import { field } from './xmlList';

/**
 * What a response says about whether it is the whole answer.
 *
 * `tokenParam` is the request parameter the token must be sent back under. It
 * is derived from the response field rather than assumed, because AWS is not
 * consistent: services on `NextToken` echo it back in `NextToken`, IAM's marker
 * lists echo the continuation in `Marker`, and EC2 has call styles using
 * `NextToken` alongside older ones using `NextMarker`.
 */
export interface TruncationSignal {
  truncated: boolean;
  nextToken: string | null;
  tokenParam: string | null;
}

const NO_TRUNCATION: TruncationSignal = { truncated: false, nextToken: null, tokenParam: null };

/**
 * Response fields AWS uses for a continuation token, in trust order. Ordered
 * because a response can carry more than one, and a stray empty field must not
 * mask a populated one.
 */
const QUERY_TOKEN_FIELDS: readonly string[] = ['NextToken', 'nextToken', 'NextMarker', 'NextPageToken', 'Marker'];

/**
 * Reads a Query-protocol (XML) response for a continuation signal.
 *
 * Pure and cheap on purpose — this runs on every AWS response in the product
 * (see the guard in awsApi.ts), so it must not parse XML, only look for the
 * handful of tags that can appear. Nesting is not a concern: none of these
 * field names occur inside a resource item's own payload.
 */
export function detectQueryTruncation(xml: string): TruncationSignal {
  if (typeof xml !== 'string' || xml.length === 0) return NO_TRUNCATION;

  // IsTruncated is the authoritative flag on marker-style APIs (IAM, S3,
  // CloudWatch Logs). A false value with no token is a complete answer.
  const isTruncated = field(xml, 'IsTruncated') === 'true';

  for (const tokenField of QUERY_TOKEN_FIELDS) {
    const token = field(xml, tokenField);
    if (token && token.trim() !== '') {
      return { truncated: true, nextToken: token, tokenParam: tokenField };
    }
  }

  // AWS said there is more but handed nothing to continue with. Reporting this
  // as complete would silently drop the remainder, so it is surfaced instead.
  if (isTruncated) return { truncated: true, nextToken: null, tokenParam: null };

  return NO_TRUNCATION;
}

/** JSON field names AWS uses for a continuation token, in trust order. */
const JSON_TOKEN_FIELDS: readonly string[] = ['NextToken', 'nextToken', 'NextMarker', 'nextMarker', 'NextPageToken', 'Marker'];

/**
 * Reads a JSON-protocol response for a continuation signal.
 *
 * Only the ROOT object is inspected. Pagination metadata is always top-level,
 * while a nested `marker` or `truncated` key is a resource's own field — the
 * distinction matters because a false positive here would degrade a scanner's
 * coverage and freeze its cleanup.
 */
export function detectJsonTruncation(body: unknown): TruncationSignal {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) return NO_TRUNCATION;
  const root = body as Record<string, unknown>;

  const isTruncated = root.IsTruncated === true || root.isTruncated === true || root.truncated === true;

  for (const tokenField of JSON_TOKEN_FIELDS) {
    const value = root[tokenField];
    if (typeof value === 'string' && value.trim() !== '') {
      return { truncated: true, nextToken: value, tokenParam: tokenField };
    }
  }

  if (isTruncated) return { truncated: true, nextToken: null, tokenParam: null };
  return NO_TRUNCATION;
}

/**
 * Text a JSON-protocol call should scan for truncation. A caller may already
 * hold parsed JSON or a raw string; both are accepted, and a string is tried as
 * JSON first so a JSON body that arrived as text is not misread as XML.
 */
export function detectTruncation(body: unknown): TruncationSignal {
  if (typeof body === 'string') {
    const trimmed = body.trim();
    if (trimmed.startsWith('{')) return detectJsonTruncation(safeJsonParse(trimmed));
    return detectQueryTruncation(body);
  }
  return detectJsonTruncation(body);
}

function safeJsonParse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}
