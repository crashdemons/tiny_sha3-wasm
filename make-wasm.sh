rm -rf sha3-wasm-dist
mkdir sha3-wasm-dist
emcc -O3 -flto -s MODULARIZE=1 -s 'EXPORT_NAME="createSha3Module"' -s WASM=1 -s EXTRA_EXPORTED_RUNTIME_METHODS='["cwrap"]' sha3.c -o sha3-wasm-lib.c -o sha3-wasm-dist/sha3-wasm.js

cat sha3-wasm-dist/sha3-wasm.js sha3-js-wrapper/sha3-wrapper.js > sha3-wasm-dist/sha3-wrapped.js
