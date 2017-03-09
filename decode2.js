'use strict';

const fs = require('fs');
const jose = require('node-jose');
const MetadataStatement = require('./lib/MetadataStatement');
const Logger = require('./lib/Logger');

const log = Logger.getLogger();

const requestraw = JSON.parse(fs.readFileSync('./var/example-clientregistration.txt', 'utf8'));
const jwks = JSON.parse(fs.readFileSync('./var/example-jwks.json', 'utf8'));
const keystore = jose.JWK.createKeyStore();
const request = new MetadataStatement('clientRegistrationRequest', requestraw);

log.info(typeof MetadataStatement, 'typeof MetadataStatement');

log.info(request.toJSON(), 'Client registration request.');
Promise.all(jwks.map(k => keystore.add(k)))
  .then(() => request.decode(keystore))
  .then((result) => {
    log.info('----- Result ----');
    // log.info(keystore.all(), 'Resulting keystore');
    log.info({ ms: result.map(r => r.toJSON()) }, 'Resulting Metadata Statements');
  })
  .catch((err) => {
    log.error(err, 'Error');
  });
