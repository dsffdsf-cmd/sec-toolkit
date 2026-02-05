import type { HttpRequest } from '../../main/proxy-server';

/**
 * Compare two requests for detail-panel rendering.
 * Returns true when the detail view can skip re-render (same logical request and content).
 * Used so adding new requests to the list does not cause code snippets / detail UI to reload.
 */
export function requestDetailEqual(a: HttpRequest | null | undefined, b: HttpRequest | null | undefined): boolean {
  if (a === b) return true;
  if (!a || !b) return false;
  if (a.id !== b.id) return false;
  // Same request id: only re-render when body/response actually changed (e.g. response arrived)
  const aBodyLen = (a.body?.length ?? 0);
  const bBodyLen = (b.body?.length ?? 0);
  const aRespLen = (a.responseBody?.length ?? 0);
  const bRespLen = (b.responseBody?.length ?? 0);
  return aBodyLen === bBodyLen && aRespLen === bRespLen;
}
