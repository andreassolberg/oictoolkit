'use strict';

const fs = require('fs');
// const Federation = require('./lib/Federation');
const jose = require('node-jose');
// const MetadataStatement = require('./lib/MetadataStatement');
const MetadataStatementEncoded = require('./lib/MetadataStatementEncoded');
const Logger = require('./lib/Logger');

const log = Logger.getLogger();
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

log.info(msEncoded.toJSON(), 'Encoded Metadata Statement');
Promise.all(jwks.map(k => keystore.add(k)))
  .then(() => msEncoded.decode(keystore))
  .then((result) => {
    log.info('----- Result ----');
    log.info(keystore.all());
    log.info(result);
  })
  .catch((err) => {
    log.error(err, 'Error');
  });
