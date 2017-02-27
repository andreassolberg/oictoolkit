'use strict';

const Federation = require('./lib/Federation');

const f = new Federation();
f.setupKeys()
  .then(() => {
    f.getMS();
  })
  .catch((err) => {
    console.error(err);
  });
