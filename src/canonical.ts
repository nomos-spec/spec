/**
 * RFC 8785: JSON Canonicalization Scheme (JCS)
 * Essential for SPEC-001 compliance and hash consistency.
 */
export function canonicalize(obj: any): string {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }

  if (Array.isArray(obj)) {
    return '[' + obj.map(item => canonicalize(item)).join(',') + ']';
  }

  const sortedKeys = Object.keys(obj).sort();
  const result = sortedKeys.map(key => {
    const value = obj[key];
    if (value === undefined) return null;
    return JSON.stringify(key) + ':' + canonicalize(value);
  }).filter(Boolean);

  return '{' + result.join(',') + '}';
}

export async function digest(data: any): Promise<string> {
  const json = canonicalize(data);
  const msgUint8 = new TextEncoder().encode(json);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}
