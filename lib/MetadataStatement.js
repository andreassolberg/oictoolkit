'use strict';

const _ = require('lodash');
const jose = require('node-jose');
const uuid = require('uuid');

const JWT = require('./helpers/jwt');
const METADATA_STATEMENT = require('./consts').METADATA_STATEMENT;


const map = new WeakMap();

function instance(ctx) {
  if (!map.has(ctx)) map.set(ctx, {});
  return map.get(ctx);
}

const cartesian = function cartesian(x, y) {
  const z = [];
  for (let i = 0; i < x.length; i++) {
    for (let j = 0; j < y.length; j++) {
      z.push(_.flattenDeep([x[i], y[j]]));
    }
  }
  return z;
};


class MetadataStatement {

  constructor(id, metadata, keystore) {
    this.id = id;
    this.keystore = keystore;
    this.statements = [];
    this.encoded = null;

    const recognized = _.chain(metadata)
      .pick(METADATA_STATEMENT)
      .value();

    _.forEach(recognized, (value, key) => { instance(this)[key] = value; });


    // if (keystore !== undefined) {
    //   assert(jose.JWK.isKeyStore(keystore), 'keystore must be an instance of jose.JWK.KeyStore');
    //   instance(this).keystore = keystore;
    // }
    //
    // if (this.token_endpoint_auth_method.endsWith('_jwt')) {
    //   assert(this.issuer.token_endpoint_auth_signing_alg_values_supported,
    //     'token_endpoint_auth_signing_alg_values_supported must be provided on the issuer');
    // }

    // this.CLOCK_TOLERANCE = 0;
  }

  addSigningKeyFromKeystore() {
    const key = this.keystore.get({ kid: this.id });
    if (!instance(this).signing_keys) {
      instance(this).signing_keys = [];
    }
    if (key === null) {
      console.log('Could not find key from keystore for ' + this.id);
    }
    instance(this).signing_keys.push(key);
  }

  setEncoded(encoded) {
    this.encoded = encoded;
  }

  // static getAllKeys(input, existingKeystore) {
  //   let keystore;
  //   if (existingKeystore) {
  //     keystore = existingKeystore;
  //   } else {
  //     keystore = jose.JWK.createKeyStore();
  //   }
  //
  //   let parts = /([^.]+)\.([^.]+)\.([^.]+)/.exec(input);
  //   parts = _.drop(parts, 1).map(jose.util.base64url.decode).map(buf => buf.toString('utf-8'));
  //   console.log('     -   - -- -- - -- -- - -');
  //   console.log(parts);
  //   console.log('     -   - -- -- - -- -- - -');
  //
  // }

  static getPayload(input) {
    return JWT.decode(input).payload;
    // const parts = /([^.]+)\.([^.]+)\.([^.]+)/.exec(input);
    // return JSON.parse(jose.util.base64url.decode(parts[1]).toString('utf-8'));
  }

  /*
   * From a raw JSON MS payload, extract the signing_keys parameter,
   * and return a JOSE Keystore object.
   */
  getKeystore() {
    const payload = instance(this);
    const keystore = jose.JWK.createKeyStore();
    if (payload.signing_keys) {
      // console.log("KEYS", payload.signing_keys);
      return Promise.all(
        payload.signing_keys.map((signingKey) => {
          // console.log("X: ", signingKey);
          return keystore.add(signingKey)
        })
      )
        .then(() => {
          // console.log("  ======================= KEYSTORE", keystore.all());
          return keystore;
        });
    }
    return Promise.resolve(keystore);
  }

  /*
   * Arguments: the root trusted keystore, along with a metadata statement
   * The msraw can be eigther an compact encoded JSE (signed JWT), or a plain JSON.
   *
   * Returns a promise error, or resolves to a MetadataStatement.
   */
  static decode(key, msraw) {
    // {key} can be:
    // *  jose.JWK.Key
    // *  JSON object representing a JWK
    const pl = (typeof msraw === 'string') ? MetadataStatement.getPayload(msraw) : msraw;
    const thisId = pl.iss || uuid();
    let keysToTrust = [key];
    let subMS = [];

    console.log(' ==> Decoding ', thisId);
    console.log('------------------------');
    console.log(keysToTrust.map(x => x.toJSON()));
    console.log('------------------------');

    return Promise.resolve()
      .then(() => {
        // First process all sub metadata statements.
        if (!pl.metadata_statements) return Promise.resolve();
        return Promise.all(
          pl.metadata_statements.map(ms => MetadataStatement.decode(key, ms))
        )
          .then((msresults) => {
            // console.log('Processed a set of metadata statements', msresults);
            subMS = msresults;

            return Promise.all(msresults.map(msy => msy.getKeystore()));
          })
          .then((ktt) => {
            console.log(' >>>> =', ktt);
            keysToTrust = ktt;
          });
      })
      .then(() => {
        // Now all sub metadata statements are processed.
        const thisMS = new MetadataStatement(thisId, pl, key);
        subMS.forEach((sm) => {
          thisMS.addMetadataStatement(sm);
        });
        if (typeof msraw !== 'string') return Promise.resolve(thisMS);
        if (_.size(keysToTrust) < 1) throw new Error('Should contain at least one key to trust in order to verify the chain.');
        thisMS.setEncoded(msraw);

        console.log('------------------------');
        console.log('----- keys to trust ----');
        console.log('------------------------');
        console.log(pl);
        console.log('------------------------');
        console.log(keysToTrust.map(k => console.log(k)));
        console.log('------------------------');

        return Promise.all(
          keysToTrust.map(oneKey => jose.JWS.createVerify(oneKey)
              .verify(msraw)
              .then((result) => {
                console.log('Signature validation result: ', result);
                return result;
              })
            )
        )
        .then(() => thisMS);
      });

    // TODO: Support metadata_statements URLs
    // console.log('----- decoding ----');
    // console.log(pl);

    // console.log('----- Sub MS ----');
    // console.log(subMS);
  }

  addMetadataStatement(statement) {
    this.statements.push(statement);
  }

  sign(audience) {
    const payload = instance(this);
    const key = this.keystore.get({ kid: payload.iss });

    const aud = audience || null;
    const alg = 'RS256';

    // console.log('===> About to sign with this key', key);
    // console.log(payload);

    // payload.signing_keys = [];
    // payload.signing_keys.push(key);

    return (() => {
      if (this.statements.length > 0) {
        payload.metadata_statements = [];
        return Promise.all(
          this.statements.map(statement =>
            statement.sign(payload.iss)
              .then((signed) => {
                payload.metadata_statements.push(signed);
                return signed;
              })
          )
        );
      }

      return Promise.resolve();
    })()
    .then(() =>
      JWT.sign(payload, key, alg, {
        audience: aud,
        expiresIn: 3600,
        issuer: payload.iss,
      })
    )
    .then((signed) => {
      // console.log('Signed', signed);
      return signed;
    })
    .catch((err) => {
      console.log('Err', err);
    });
  }

  getPlain() {
    const payload = instance(this);
    // const key = this.keystore.get({ kid: payload.iss });
    //
    // payload.signing_keys = [];
    // payload.signing_keys.push(key);

    if (this.statements.length > 0) {
      payload.metadata_statements = this.statements.map(statement => statement.getPlain());
    }
    return payload;
  }

  getVisualProperties() {
    const data = [];
    const payload = instance(this);

    Object.keys(payload).forEach((key) => {
      const x = { key };
      if (key === 'signing_keys') {
        x.valuejson = JSON.stringify(payload[key], undefined, 2);
      } else {
        x.value = JSON.stringify(payload[key], undefined, 2);
      }
      data.push(x);
    });

    // for (let key in payload) {
    //   if (Object.prototype.hasOwnProperty.call(payload, key)) {
    //     data[key] = JSON.stringify(payload[key]);
    //   }
    // }
    return data;
  }

  getPaths() {
    let paths = [];
    if (this.statements.length > 0) {
      // console.log('PROCESSING PATH', paths);
      this.statements.forEach((st) => {
        paths = _.concat(paths, cartesian([this.id], st.getPaths()));
        // console.log('PROCESSING SUBpaths', mp);
      });
      // console.log("Subpaths is ", subpaths);
      // paths = cartesian(paths, subpaths);
    } else {
      paths.push([this.id]);
    }
    return paths;
  }

  getStructured() {
    const payload = instance(this);

    const data = {
      plain: this.getVisualProperties(),
      raw: this.getPlain()
    };

    data.id = this.id;
    if (payload.iss) {
      data.iss = payload.iss;
    }
    data.signing_keys = payload.signing_keys;

    return (() => {
      if (this.statements.length > 0) {
        data.metadata_statements = [];
        return Promise.all(
          this.statements.map(statement =>
            statement.getStructured()
              .then((str) => {
                data.metadata_statements.push(str);
              })
          )
        );
      }
      return Promise.resolve();
    })()
    .then(() => {
      if (!data.metadata_statements) {
        data.leafNode = true;
      }
      return this.sign();
    })
    .then((signed) => {
      data.signed = signed;
      return data;
    });
  }

  getObject() {
    return instance(this);
  }

  getPlainSingle() {
    return instance(this);
  }

  getFullStructure() {
    const x = {};
    return this.getStructured().then((s) => {
      x.paths = this.getPaths();
      x.pathsJSON = x.paths.map(p => JSON.stringify(p));
      x.structured = s;
      // console.log(' ------ about to return full structure ');
      // console.log(x);
      return x;
    });
  }

}


module.exports = MetadataStatement;
