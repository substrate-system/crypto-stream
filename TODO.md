# Audit follow-up tasks

From the correctness audit on 2026-07-02. The build script fix
(commit 99108a7) resolved the broken package entry points; both
`import` and `require` of the bare package now work. These are the
remaining items, highest priority first.

## Build

1. [x] Emit type declarations again. The esbuild-only build produces no
   `.d.ts` files, so TypeScript consumers get no types (the old `tsc`
   build emitted them). Add a declaration-only step, e.g.
   `tsc --emitDeclarationOnly --project tsconfig.build.json`, and set
   `rootDir: "./src"` with `include: ["src/**/*"]` in
   `tsconfig.build.json` so declarations land flat in `dist/` next to
   the JS. Consider adding a `types` field to `package.json` exports.
2. [x] Make the CJS build self-contained. `dist/index.cjs` contains
   `require("./keychain.js")`, which resolves to the ESM file because
   esbuild does not rewrite specifiers when transpiling per-file. This
   works on Node >= 20.17 (require of ESM) but fails on older Node and
   some bundler CJS paths. Either bundle the CJS entry
   (`esbuild --bundle --packages=external`) or rewrite the `.js`
   specifiers to `.cjs` in the CJS output.

## README

3. [x] Fix the "Example With Blobs" snippet (README.md:98-111). It uses
   `keychain` without ever constructing it. Show
   `const keychain = new Keychain(key, salt)` and note that decryption
   requires the same key and salt that encrypted the file. Also rename
   `encryptedData` to `response` (it is a `Response`, not data).

4. [x] Fix the ece import path in the Seek example (README.md:133) and the
   "Low-level ECE building blocks" section (README.md:634-635). With
   the new flat `dist/` layout, `@substrate-system/crypto-stream/src/ece`
   no longer resolves. The working subpath is
   `@substrate-system/crypto-stream/ece` (verified).

5. [x] Fix the `decryptStreamRange` docs (README.md:474-502). The TS block
   shows the low-level `ece.ts` function signature (with `secretKey`
   and `rs` params) instead of the Keychain method signature
   `(offset, length, totalEncryptedLength)`. The stray
   `#### encryptedStream` parameter block below it belongs to the
   `decryptStream` section.

6. [x] Smaller doc drift: `authToken()` returns `Promise<Uint8Array>`, not
   `Promise<ArrayBuffer>` (README.md:242); `encryptBytes` docs omit the
   `size` option; `authHeader` docs omit the optional `tokenString`
   param; the static `Keychain.AuthHeader` and `Keychain.Header`
   methods are undocumented.

## API gaps

7. [x] `keychain.decryptStream` cannot decrypt streams encrypted with a
   custom `recordSize`. It calls `ece.decryptStream` with the default
   rs (65536), so the header check at src/ece.ts:245 throws for any
   other record size, and the SliceTransformer slices at the wrong
   boundaries regardless. The test suite works around this by dropping
   to `ece.decryptStream` directly (test/seekable-write.ts:731-734).
   Add `opts.recordSize` to `Keychain.decryptStream` and
   `Keychain.decryptStreamRange` (ece's versions already take `rs`),
   or document the limitation prominently in the README. Add a test
   that round-trips a custom record size through the Keychain API.

8. [x] `decryptBytes` cannot decrypt `encryptBytes` output when
   `opts.size` was used. `encryptBytes` derives a key of `opts.size`
   bytes (src/keychain.ts:312) but `decryptBytes` always derives the
   16-byte default (src/keychain.ts:325). Either accept a matching
   option in `decryptBytes` or remove `size` from `encryptBytes`.

## Example

9. [x] `example/index.ts:31` reads only the first chunk of the decrypted
   stream and builds the Blob from it. This works because
   cheesecake.jpeg (20 KB) fits in one ECE record (65,519 bytes max),
   but silently truncates anything larger. Use
   `new Response(decryptedStream).blob()` as the README shows.

## Minor code cleanups

10. [x] `encryptBytes` JSDoc (src/keychain.ts:290-300): the key is derived
    deterministically, not "generated new each time" (that is why
    `decryptBytes` works at all), and the IV is 12 bytes, not
    "12 bits". Add a SAFETY note that passing a caller-supplied `iv`
    twice with different plaintexts is AES-GCM nonce reuse under the
    same derived key.

11. [x] `plaintextSize()` (src/ece.ts:335) returns negative values for
    inputs smaller than HEADER_LENGTH with no validation.

12. [x] `transform-stream.ts` fallback path captures
    `controller.desiredSize` as a static value instead of a getter
    (src/transform-stream.ts:86). Only affects environments without
    native TransformStream.
