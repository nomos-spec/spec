import { canonicalize, digest } from './canonical';
import { Suites } from './suites';

export interface Certificate {
  issuer: string;
  subject: string;
  scope: string[];
  expires: string;
  signature: string;
  suite: string;
}

export async function resolveChain(
  targetKey: string,
  roots: Set<string>,
  certs: Certificate[],
  now: string,
  requiredScope: string
): Promise<boolean> {
  if (roots.has(targetKey)) return true;

  const validCerts = certs.filter(c => 
    c.subject === targetKey && 
    new Date(c.expires) > new Date(now) &&
    c.scope.includes(requiredScope)
  );

  for (const cert of validCerts) {
    // SPEC-007: Target-first resolution
    const { signature, ...body } = cert;
    const msg = new TextEncoder().encode(canonicalize(body));
    const sigBytes = Buffer.from(signature, 'hex');
    const issuerBytes = Buffer.from(cert.issuer, 'hex');

    const isValid = await Suites[cert.suite].verify(msg, sigBytes, issuerBytes);
    if (isValid) {
      if (await resolveChain(cert.issuer, roots, certs, now, requiredScope)) {
        return true;
      }
    }
  }
  return false;
}
