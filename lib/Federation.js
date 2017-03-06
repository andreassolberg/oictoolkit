'use strict';

const fs = require('fs');
const jose = require('node-jose');

const MetadataStatement = require('./MetadataStatement');
// const METADATA_STATEMENT = require('./consts').METADATA_STATEMENT;

class Federation {

  constructor() {
    this.keystore = jose.JWK.createKeyStore();
    // this.setupKeys()
    //   .then(() => {
    //     console.log(this.keystore.all());
    //   });
    // var m = new MetadataStatement({
    //   "redirect_uris": [
    //     "https://example.com/rp1/callback",
    //     "https://example.com/rp1/callback2"
    //   ]
    // }, keystore);
    // console.log("-----");
    // console.log(m.getObject());
  }

  setupKeys() {
    const rootKey = fs.readFileSync('./var/root.key');
    const foKey = fs.readFileSync('./var/fo.key');
    const entityKey = fs.readFileSync('./var/entity.key');
    const kalmarKey = fs.readFileSync('./var/kalmar.key');
    const ofKey = fs.readFileSync('./var/of.key');

    return Promise.all([
      this.keystore.add(rootKey, 'pem', { kid: 'https://edugain.org/' }),
      this.keystore.add(foKey, 'pem', { kid: 'https://feide.no/' }),
      this.keystore.add(entityKey, 'pem', { kid: 'https://foodl.org/' }),
      this.keystore.add(kalmarKey, 'pem', { kid: 'https://kalmar.org/' }),
      this.keystore.add(ofKey, 'pem', { kid: 'https://open_federation.org/' }),
    ]);
  }

  decode(jwks, msraw) {
    let ms;
    return MetadataStatement.decode(jwks, msraw)
      .then((x) => {
        // console.log('----- MS ----');
        // console.log(x);
        ms = x;
        return ms;
      });
  }

  getKeys() {
    return this.keystore.toJSON();
  }

  getMS() {
    const msFeideEduGAIN = new MetadataStatement('https://feide.no/', {
      iss: 'https://edugain.org/',
      id_token_signing_alg_values_supported: ['RS256', 'RS512'],
      claims: ['sub', 'name', 'email', 'picture'],
    }, this.keystore);

    const msFeideKalmar = new MetadataStatement('https://feide.no/', {
      iss: 'https://kalmar.org/',
      id_token_signing_alg_values_supported: ['RS256'],
      claims: ['sub', 'name'],
    }, this.keystore);

    const msEntity = new MetadataStatement('https://foodl.org/', {
      iss: 'https://feide.no/',
      client_name: 'Foodle polls and surveys',
      claims: ['sub', 'name', 'picture'],
      scope: 'openid eduperson',
      response_types: ['code'],
      redirect_uris: ['https://foodl.org/callback', 'https://www.foodl.org/callback'],
      contacts: ['andreas.solberg@uninett.no', 'kontakt@uninett.no'],
    }, this.keystore);

    // const msEntity2 = new MetadataStatement('https://foodl.org/', {
    //   iss: 'https://open_federation.org/',
    //   client_name: 'Foodle polls and surveys',
    //   claims: ['sub', 'name', 'picture'],
    //   scope: 'openid eduperson',
    //   response_types: ['code'],
    //   redirect_uris: ['https://foodl.org/callback', 'https://www.foodl.org/callback'],
    //   contacts: ['andreas.solberg@uninett.no', 'kontakt@uninett.no'],
    // }, this.keystore);
    //
    // const msEntity3 = new MetadataStatement('https://foodl.org/', {
    //   iss: 'https://foodl.org/',
    //   client_name: 'Foodle polls and surveys',
    //   claims: ['sub'],
    //   scope: 'openid eduperson',
    //   response_types: ['code'],
    //   redirect_uris: ['https://foodl.org/callback', 'https://www.foodl.org/callback'],
    //   contacts: ['andreas.solberg@uninett.no', 'kontakt@uninett.no'],
    // }, this.keystore);


    msFeideKalmar.addSigningKeyFromKeystore();
    msFeideEduGAIN.addSigningKeyFromKeystore();
    msEntity.addSigningKeyFromKeystore();
    // msEntity2.addSigningKeyFromKeystore();
    // msEntity3.addSigningKeyFromKeystore();

    msEntity.addMetadataStatement(msFeideEduGAIN);
    msEntity.addMetadataStatement(msFeideKalmar);
    // msEntity3.addMetadataStatement(msEntity2);

    // return msEntity.get();
    // return Promise.resolve(msEntity.getStructured(id));

    // return Promise.resolve([msEntity, msEntity2, msEntity3]);
    return Promise.resolve([msEntity]);
      // .then((signed) => {
      //   console.log('Signed MS');
      //   console.log(signed);
      // });
  }

}


module.exports = Federation;
