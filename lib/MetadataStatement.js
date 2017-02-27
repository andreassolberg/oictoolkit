'use strict';

const _ = require('lodash');
const jose = require('node-jose');


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

    const recognized = _.chain(metadata)
      .pick(METADATA_STATEMENT)
      .value();

    _.forEach(recognized, (value, key) => { instance(this)[key] = value; });

    if (id) {
      const key = this.keystore.get({ kid: id });
      if (!instance(this).signing_keys) {
        instance(this).signing_keys = [];
      }
      if (key === null) {
        console.log('Could not find key from keystore for ' + id);
      }
      instance(this).signing_keys.push(key);
    }

    console.log(instance(this));

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

  static getAllKeys(input, existingKeystore) {
    let keystore;
    if (existingKeystore) {
      keystore = existingKeystore;
    } else {
      keystore = jose.JWK.createKeyStore();
    }

    let parts = /([^.]+)\.([^.]+)\.([^.]+)/.exec(input);
    parts = _.drop(parts, 1).map(jose.util.base64url.decode).map(buf => buf.toString('utf-8'));
    console.log('     -   - -- -- - -- -- - -');
    console.log(parts);
    console.log('     -   - -- -- - -- -- - -');

  }

  static decode(key, msraw) {
    // {key} can be:
    // *  jose.JWK.Key
    // *  JSON object representing a JWK
    console.log("YAY, we verify with this key", key);
    console.log("msraw", msraw);
    var allKeys = MetadataStatement.getAllKeys(msraw);

    return jose.JWS.createVerify(key)
      .verify(msraw)
      .then((result) => {
        console.log('RESULT IS ', result);
        return result;
      });
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

  getStructured(audience) {
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
            statement.getStructured(payload.iss)
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

  getFullStructure() {
    const x = {};
    return this.getStructured().then((s) => {
      x.paths = this.getPaths();
      x.pathsJSON = x.paths.map(p => JSON.stringify(p));
      x.structured = s;
      console.log(' ------ about to return full structure ');
      console.log(x);
      return x;
    });
  }

}


module.exports = MetadataStatement;
