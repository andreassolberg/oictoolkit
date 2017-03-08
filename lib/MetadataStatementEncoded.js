'use strict';

const _ = require('lodash');
const jose = require('node-jose');
const uuid = require('uuid');

const MetadataStatement = require('./MetadataStatement');
const SignatureValidationException = require('./exceptions/SignatureValidationException');
const JWT = require('./helpers/jwt');
const Logger = require('./Logger');

class MetadataStatementEncoded {

  constructor(value) {
    this.value = value;
    this.log = Logger.getLogger();
  }

  toJSON() {
    return _.omit(this, ['log']);
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
  decode(rootKeystore, parentIssuer) {
    const payload = JWT.decode(this.value).payload;
    const cleanPayload = _.omit(payload, ['metadata_statements', 'metadata_statements_urls']);
    const thisId = parentIssuer || payload.sub || uuid();

    this.log.info(' ==> Decoding ', thisId);
    // if (payload.signing_keys) {
    //   // console.log(' ====> Signingkeys ', payload.signing_keys);
    // }

    // We have reached the innermost MS with no embedded MS to parse.
    // We will validate this MS with the root trust keystore provided.
    if (!payload.metadata_statements) {
      return jose.JWS.createVerify(rootKeystore)
        .verify(this.value)
        .then((result) => {
          this.log.info('Innermost signature validation result: ', result);
          return [new MetadataStatement(thisId, cleanPayload)];
        })
        .catch((err) => {
          this.log.error('Error verifying innermost signature');
          this.log.error(err);
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
                  this.log.info('Signature validation result: ', result);
                  const ms = new MetadataStatement(thisId, cleanPayload);
                  ms.addMetadataStatement(subms);
                  return ms;
                })
                .catch((err) => {
                  const errorContext = {
                    'This is the embedded trusted MS that is alerady validated and contain signing keys:': subms.getPlainSingle(),
                    'Trust store': submsTrust.all(),
                    'Error verifying this signed MS': JWT.decode(this.value),
                    error: err.message,
                    stack: err.stack,
                  };
                  this.log.error(errorContext, 'Failed to validate signature');
                  const sve = new SignatureValidationException('Failed to validate signature');
                  sve.setError(err);
                  sve.setContext(errorContext);
                  return Promise.reject(sve);
                });
            });
        }));
      });
  }
}


module.exports = MetadataStatementEncoded;
