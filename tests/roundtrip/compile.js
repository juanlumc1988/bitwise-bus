// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// Compiles a Kaitai Struct definition to Python with the official compiler, the
// JavaScript build of it (npm: kaitai-struct-compiler). The compiler takes the
// definition as an object, so the caller gives it as JSON: a YAML file that
// has been parsed, which is also what says the YAML is valid.
//
//   node compile.js COMPILER_MODULE DEFINITION.json OUTPUT_DIR

'use strict';

const fs = require('fs');
const path = require('path');

if (process.argv.length !== 5) {
    console.error('usage: node compile.js COMPILER_MODULE DEFINITION.json OUTPUT_DIR');
    process.exit(2);
}

const compiler = require(path.resolve(process.argv[2]));
const definition = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
const outputDir = process.argv[4];

compiler.compile('python', definition, null, false).then((files) => {
    for (const name of Object.keys(files)) {
        fs.writeFileSync(path.join(outputDir, name), files[name]);
    }
}).catch((error) => {
    console.error(String(error));
    process.exit(1);
});
