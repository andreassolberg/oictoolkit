'use strict';

const fs = require('fs');
const jose = require('node-jose');
const prettyjson = require('prettyjson');

const Federation = require('./lib/Federation');
const MetadataStatement = require('./lib/MetadataStatement');
const MetadataStatementEncoded = require('./lib/MetadataStatementEncoded');

const f = new Federation();

f.setupKeys()
  .then(() => {
    return f.getMS();
  })
  .then((signed) => {
    console.log('---- Signed MS ----');
    signed.forEach((ms) => {
      console.log('');
      console.log('   -----> Metadata Statement <-----');
      console.log(prettyjson.render(ms.getPlainSingle()));
      console.log('');
    });
  })
  .catch((err) => {
    console.error(err);
  });

// const ms = fs.readFileSync('./var/example-ms.txt', 'utf8');
// const jwks = JSON.parse(fs.readFileSync('./var/example-jwks.json', 'utf8'));
// const keystore = jose.JWK.createKeyStore();
// const msEncoded = new MetadataStatementEncoded(ms);

// const m = new MetadataStatement('x', MetadataStatement.getPayload(ms), keystore);
// m.getKeystore()
//   .then((k) => {
//     console.log('----- Result ----');
//     console.log(k);
//   });

// console.log("----");
// console.log(msEncoded);
//
// Promise.all(jwks.map(k => keystore.add(k)))
//   .then(() => msEncoded.decode(keystore))
//   .then((result) => {
//     console.log('----- Result ----');
//     console.log(keystore.all());
//     console.log(result);
//   })
//   .catch((err) => {
//     console.error('Error', err);
//   });
