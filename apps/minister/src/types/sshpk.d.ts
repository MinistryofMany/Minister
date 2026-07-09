// Minimal ambient types for the subset of `sshpk` the public-key plugin uses.
// The package ships no types and `@types/sshpk` is not installed (adding a dep
// is out of scope here), so this declares only the surface we call. `skipLibCheck`
// keeps this from being deeply validated; it exists to satisfy the strict app
// typecheck without an `any` cast at the import site.
declare module "sshpk" {
  export interface Fingerprint {
    toString(format?: string): string;
  }

  export interface Signature {
    toBuffer(format?: string): Buffer;
  }

  export interface Verifier {
    update(data: Buffer | string): void;
    verify(signature: Signature): boolean;
  }

  export interface Key {
    readonly type: string;
    readonly size: number;
    readonly curve?: string;
    toBuffer(format?: string): Buffer;
    fingerprint(algorithm?: string): Fingerprint;
    createVerify(hashAlgorithm?: string): Verifier;
  }

  export function parseKey(data: string | Buffer, format?: string): Key;
  export function parseSignature(data: Buffer, algorithm: string, format: string): Signature;

  export class KeyParseError extends Error {}
  export class SignatureParseError extends Error {}
  export class FingerprintFormatError extends Error {}
  export class InvalidAlgorithmError extends Error {}
}
