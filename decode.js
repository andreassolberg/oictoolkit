'use strict';

const fs = require('fs');
// const Federation = require('./lib/Federation');
const jose = require('node-jose');
// const MetadataStatement = require('./lib/MetadataStatement');
const MetadataStatementEncoded = require('./lib/MetadataStatementEncoded');

// const f = new Federation();

// f.setupKeys()
//   .then(() => {
//     f.getMS();
//   })
//   .catch((err) => {
//     console.error(err);
//   });

const ms = fs.readFileSync('./var/example-ms2.txt', 'utf8');
const jwks = JSON.parse(fs.readFileSync('./var/example-jwks.json', 'utf8'));
const keystore = jose.JWK.createKeyStore();
const msEncoded = new MetadataStatementEncoded(ms);

// const m = new MetadataStatement('x', MetadataStatement.getPayload(ms), keystore);
// m.getKeystore()
//   .then((k) => {
//     console.log('----- Result ----');
//     console.log(k);
//   });


console.log(msEncoded);

Promise.all(jwks.map(k => keystore.add(k)))
  .then(() => msEncoded.decode(keystore))
  .then((result) => {
    console.log('----- Result ----');
    console.log(keystore.all());
    console.log(result);
  })
  .catch((err) => {
    console.error('Error', err);
  });