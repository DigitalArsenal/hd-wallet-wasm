/*
 * DISPLAY FORMATTING for external accounts — pure, so the rendered text is a
 * computable outcome. The FULL value stays the identity everywhere; this is
 * display-only truncation (the copy affordance always copies the full value).
 */

/** '0x8ba1f109…4DBA72' — head + ellipsis + tail, or the value verbatim when
 *  it is already short enough that truncating would hide nothing. */
export function truncateMiddle(value, head = 8, tail = 6) {
  const text = String(value ?? '');
  if (text.length <= head + tail + 1) return text;
  return `${text.slice(0, head)}…${text.slice(-tail)}`;
}
