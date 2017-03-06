'use strict';

const express = require('express');
const Federation = require('./Federation');
const _ = require('lodash');

class App {

  constructor(opts) {
    this.opts = opts || {};
    this.router = express.Router();
    this.router.get('/', (req, res) => this.frontpage(req, res));
    this.router.get('/generate', (req, res) => this.generate(req, res));
    this.router.get('/decode', (req, res) => this.decode(req, res));
    this.router.post('/decode', (req, res) => this.decodePost(req, res));

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
    console.log('Data', data);
    data.pagetitle = 'OIC Federation Toolkit';
    res.render('frontpage', data);
  }

  generate(req, res) {
    // let statement;
    // let structured;
    this.fed.getMS()
      .then(msList => Promise.all(msList.map(ms => ms.getFullStructure())))
      .then((mslistdata) => {
        console.log('--------------_-> ', mslistdata, ' <-----------------');
        console.log(mslistdata);
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
        console.error('ERROR', err);
        throw new Error(err);
      });
  }

  decode(req, res) {
    const data = App.getCommonAttributes(req, 'decode');
    data.pagetitle = 'Decoding Metadata Statements';
    res.render('decode', data);
  }

  decodePost(req, res) {
    const data = App.getCommonAttributes(req, 'decode');
    data.pagetitle = 'Decoding Metadata Statements';

    const jwks = JSON.parse(req.body.jwks);
    const ms = req.body.ms;

    console.log('------ jwks');
    console.log(jwks);
    console.log(' ----- ms');
    console.log(ms);

    this.fed.decode(jwks, ms)
    .then((result) => {
      data.result = result;
      // data.mss = JSON.stringify(structured, undefined, 2);
      // data.ms = structured;
      // data.paths = JSON.stringify(paths, undefined, 2);
      res.render('decode', data);
    })
    .catch((err) => {
      console.error('ERROR', err);
      throw new Error(err);
    });
  }

  getRouter() {
    return this.router;
  }


}

module.exports = App;
