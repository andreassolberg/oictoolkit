'use strict';

const _ = require('lodash');
const jose = require('node-jose');
// const uuid = require('uuid');
const Logger = require('./Logger');

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
    this.log = Logger.getLogger();

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

  toJSON() {
    return _.omit(this, ['log', 'statements', 'keystore']);
  }

  addSigningKeyFromKeystore() {
    const key = this.keystore.get({ kid: this.id });
    this.log.info('MetadataStatement addSigningKeyFromKeystore');
    if (!instance(this).signing_keys) {
      instance(this).signing_keys = [];
    }
    if (key === null) {
      this.log.error('MetadataStatement Could not find key from keystore for ' + this.id);
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
          return keystore.add(_.assignIn({}, signingKey))
        })
      )
        .then(() => {
          // console.log("  ======================= KEYSTORE", keystore.all());
          return keystore;
        });
    }
    return Promise.resolve(keystore);
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
      this.log.error(err, 'Error signing metadata statment');
    });
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
    const payload = instance(this);
    if (this.statements.length > 0) {
      // console.log('PROCESSING PATH', paths);
      this.statements.forEach((st) => {
        paths = _.concat(paths, cartesian([this.id], st.getPaths()));
        // console.log('PROCESSING SUBpaths', mp);
      });
      // console.log("Subpaths is ", subpaths);
      // paths = cartesian(paths, subpaths);
    } else {
      paths.push([this.id, payload.iss]);
    }
    return paths;
  }

  isLeafNode() {
    return _.size(this.statements) < 1;
  }

  getPath() {
    const paths = this.getPaths();
    return paths[0];
  }

  getPathStr() {
    return this.getPath().join(' > ');
  }

  getStructured(doSign) {
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
            statement.getStructured(doSign)
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
      if (doSign) {
        return this.sign();
      }
      return Promise.resolve(null);
    })
    .then((signed) => {
      if (signed !== null) {
        data.signed = signed;
      }
      return data;
    });
  }

  getObject() {
    return instance(this);
  }

  getPlainSingle() {
    return instance(this);
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


  getFullStructure(doSign) {
    const x = {};
    return this.getStructured(doSign).then((s) => {
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
