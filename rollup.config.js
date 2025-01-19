import commonjs from '@rollup/plugin-commonjs';
import resolve from '@rollup/plugin-node-resolve';
import terser from '@rollup/plugin-terser';
import typescript from '@rollup/plugin-typescript';

export default {
  input: 'src/index.ts',
  output: [
    {
      file: 'dist/index.js',
      format: 'esm',
      sourcemap: true
    },
    {
      file: 'dist/index.cjs',
      format: 'cjs',
      sourcemap: true
    }
  ],
  external: [
    'crypto',
    'buffer',
    'stream',
    'util',
    'events',
    'jsonwebtoken',
    'uuid',
    'node:crypto',
    'node:events'
  ],
  plugins: [
    typescript({
      tsconfig: './tsconfig.json',
      declaration: true,
      declarationDir: 'dist/types',
      exclude: ['test.ts', 'test/**/*', '**/*.test.ts']
    }),
    resolve({
      preferBuiltins: true
    }),
    commonjs(),
    terser()
  ]
}