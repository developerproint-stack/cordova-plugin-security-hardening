// Node script to generate SHA-256 hashes for all files in www/ and output manifest.json
// Usage: node generate-www-hashes.js <www-folder> > www-hash-manifest.json

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function walkDir(dir, cb) {
  fs.readdirSync(dir).forEach(f => {
    const full = path.join(dir, f);
    if (fs.statSync(full).isDirectory()) walkDir(full, cb);
    else cb(full);
  });
}

const www = process.argv[2] || 'www';
let out = {};
walkDir(www, (file) => {
  const rel = path.relative(www, file).replace(/\\/g, '/');
  const buf = fs.readFileSync(file);
  const h = crypto.createHash('sha256').update(buf).digest('hex').toUpperCase();
  out[rel] = h;
});
console.log(JSON.stringify(out, null, 2));
