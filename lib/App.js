'use strict';

const express = require('express');
const _ = require('lodash');
const fs = require('fs');
const jose = require('node-jose');

const Federation = require('./Federation');
const MetadataStatementEncoded = require('./MetadataStatementEncoded');
const SignatureValidationException = require('./exceptions/SignatureValidationException');
const Logger = require('./Logger');

class App {

  constructor(opts) {
    this.opts = opts || {};
    this.router = express.Router();
    this.router.get('/', (req, res) => this.frontpage(req, res));
    this.router.get('/generate', (req, res) => this.generate(req, res));
    this.router.get('/decode', (req, res) => this.decode(req, res));
    this.router.post('/decode', (req, res) => this.decodePost(req, res));

    this.log = Logger.getLogger();

    this.fed = new Federation();
    this.fed.setupKeys();
  }

  static getCommonAttributes(req, selectedMenuitem) {
    const data = {};
    data.title = 'OpenID Federation';
    data.authenticated = !!req.user;
    if (req.user) {
      data.user = req.user.data;
      data.groups = req.groups;
    }

    const menu = {
      frontpage: {
        t: 'Frontpage',
        href: '/',
      },
      generate: {
        t: 'Generate',
        href: '/generate',
      },
      decode: {
        t: 'Decode',
        href: '/decode',
      },
    };
    _.forEach(menu, (item, key) => {
      menu[key].active = (key === selectedMenuitem);
    });
    data.menu = _.values(menu);
    return data;
  }

  frontpage(req, res) {
    const data = App.getCommonAttributes(req, 'frontpage');
    this.log.info(data, 'Frontpage view data');
    data.pagetitle = 'OIC Federation Toolkit';
    res.render('frontpage', data);
  }

  generate(req, res) {
    // let statement;
    // let structured;
    this.fed.getMS()
      .then(msList => Promise.all(msList.map(ms => ms.getFullStructure(true))))
      .then((mslistdata) => {

        this.log.info(mslistdata, 'Generate data');
        const data = App.getCommonAttributes(req, 'generate');
        data.pagetitle = 'Generating Metadata Statements';
        data.mslistdataJSON = JSON.stringify(mslistdata, undefined, 2);
        data.mslistdata = mslistdata;

        data.allKeys = this.fed.getKeys().keys.map(k => JSON.stringify([k], undefined, 2));

        // data.allKeys = JSON.stringify(this.fed.getKeys(), undefined, 2);
        // data.mss = JSON.stringify(structured, undefined, 2);
        // data.ms = structured;
        // data.paths = JSON.stringify(paths, undefined, 2);
        res.render('metadatastatements', data);
      })
      .catch((err) => {
        this.log.error(err, 'ERROR');
        throw new Error(err);
      });
  }

  decode(req, res) {
    const data = App.getCommonAttributes(req, 'decode');
    data.pagetitle = 'Decoding Metadata Statements';
    data.exampleMS = fs.readFileSync('./var/example-ms2.txt', 'utf8');
    data.exampleJWKS = fs.readFileSync('./var/example-jwks.json', 'utf8');

    res.render('decode', data);
  }

  decodePost(req, res) {
    const data = App.getCommonAttributes(req, 'decode');
    data.pagetitle = 'Decoding Metadata Statements';

    let jwks = null;
    const ms = req.body.ms;

    const keystore = jose.JWK.createKeyStore();
    let msEncoded = null;

    Promise.resolve()
      .then(() => {
        jwks = JSON.parse(req.body.jwks);
        msEncoded = new MetadataStatementEncoded(ms);
        data.exampleMS = ms;
        data.exampleJWKS = JSON.stringify(jwks, undefined, 2);

        return Promise.all(jwks.map(k => keystore.add(k)));
      })
      .then(() => msEncoded.decode(keystore))
      .then((msList) => {
        data.mslistindex = msList.map(msx => msx.getPathStr());
        return msList;
      })
      .then(msList => Promise.all(msList.map(msitem => msitem.getFullStructure(false))))
      .then((mslistdata) => {
        this.log.info(mslistdata, 'Decoded data');
        // console.log('----- Result ----');
        // console.log(keystore.all());
        // console.log(mslist);
        data.mslistdata = mslistdata;
        res.render('decode', data);
      })
      .catch((err) => {
        this.log.info(err, 'Error decoding data');
        if (err instanceof SignatureValidationException) {
          data.error = err.getErrorContextView();
          data.errorjson = JSON.stringify(err.errorContext, undefined, 2);
        } else {
          data.error = {
            title: err.message,
            stack: err.stack,
          };
        }

        res.render('decode', data);
      });
  }

  getRouter() {
    return this.router;
  }


}

module.exports = App;
