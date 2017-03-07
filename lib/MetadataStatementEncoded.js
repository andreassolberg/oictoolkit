'use strict';

const _ = require('lodash');
const jose = require('node-jose');
const uuid = require('uuid');

const MetadataStatement = require('./MetadataStatement');
const JWT = require('./helpers/jwt');


class MetadataStatementEncoded {

  constructor(value) {
    this.value = value;
  }

  // getMS() {
  //
  // }

  static fromArray(arr) {
    return arr.map(str => new MetadataStatementEncoded(str));
  }

  /*
   * Arguments: the root trusted keystore, along with a metadata statement
   * The msraw can be eigther an compact encoded JSE (signed JWT), or a plain JSON.
   *
   * Returns a promise error, or resolves to a list of MetadataStatement-s.
   * Each returned MS will only contain one nested path of MS-es.
   */
  decode(rootKeystore) {
    const payload = JWT.decode(this.value).payload;
    const cleanPayload = _.omit(payload, ['metadata_statements', 'metadata_statements_urls']);
    const thisId = payload.sub || uuid();

    console.log(' ==> Decoding ', thisId);
    if (payload.signing_keys) {
      console.log(' ====> Signingkeys ', payload.signing_keys);
    }

    // We have reached the innermost MS with no embedded MS to parse.
    // We will validate this MS with the root trust keystore provided.
    if (!payload.metadata_statements) {
      return jose.JWS.createVerify(rootKeystore)
        .verify(this.value)
        .then((result) => {
          console.log('Innermost signature validation result: ', result);
          return [new MetadataStatement(thisId, cleanPayload)];
        })
        .catch((err) => {
          console.error('Error verifying innermost signature');
          console.error(err);
        });
    }

    // We process the sub metadata statements.
    return Promise.all(
      MetadataStatementEncoded.fromArray(payload.metadata_statements)
        .map(encodedSubMS => encodedSubMS.decode(rootKeystore))
    )
      .then((submslist) => {
        submslist = _.flatten(submslist);
        // console.log(' submslist => ', submslist);
        return Promise.all(submslist.map((subms) => {
          // console.log(' subms => ', subms);
          return subms.getKeystore()
            .then((submsTrust) => {
              // console.log('-');
              return jose.JWS.createVerify(submsTrust)
                .verify(this.value)
                .then((result) => {
                  console.log('Signature validation result: ', result);
                  const ms = new MetadataStatement(thisId, cleanPayload);
                  ms.addMetadataStatement(subms);
                  return ms;
                })
                .catch((err) => {
                  console.error('--- X --- X --- X --- X --- X --- X --- X --- X --- X --- X --- X --- X');
                  console.error('This is the embedded trusted MS that is alreasdy validated and contain signing keys:');
                  console.error(subms.getPlainSingle());
                  console.error('-------');
                  console.error('--- Trust store includes', submsTrust.all());
                  console.error('-------');
                  console.error('Error verifying this signed MS: ');
                  console.error(JWT.decode(this.value));
                  console.error('-------');
                  console.error(err);
                  console.error('--- X --- X --- X --- X --- X --- X --- X --- X --- X --- X --- X --- X');
                });
            });
        }));
      });
  }
}


module.exports = MetadataStatementEncoded;
