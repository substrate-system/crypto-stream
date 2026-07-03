/**
 * esbuild transpiles src/*.ts to dist/*.cjs one file at a time, so it
 * never rewrites the relative import specifiers -- each output .cjs
 * file still contains `require("./foo.js")`, which resolves to the
 * ESM sibling instead of the CJS one. Node >= 20.17 allows require()
 * of ESM and papers over this, but older Node and some bundlers do
 * not. Rewrite those specifiers to `.cjs` after the build so the CJS
 * output is self-contained.
 */
import { readdir, readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'

const distDir = new URL('../dist', import.meta.url).pathname
const specifierPattern = /require\((["'])(\.\.?\/[^"']+)\.js\1\)/g

const files = (await readdir(distDir)).filter(f => f.endsWith('.cjs'))

for (const file of files) {
    const path = join(distDir, file)
    const contents = await readFile(path, 'utf8')
    const fixed = contents.replace(
        specifierPattern,
        (_match, quote, specifier) => `require(${quote}${specifier}.cjs${quote})`
    )

    if (fixed !== contents) await writeFile(path, fixed, 'utf8')
}
