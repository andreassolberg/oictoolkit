'use strict';

const fs = require('fs');
const Federation = require('./lib/Federation');

const f = new Federation();
f.setupKeys()
  .then(() => {
    f.getMS();
  })
  .catch((err) => {
    console.error(err);
  });


const ms = fs.readFileSync('./var/example-ms.txt', 'utf8');
const jwks = JSON.parse(fs.readFileSync('./var/example-jwks.json', 'utf8'));

f.decode(jwks, ms)
.then((result) => {
  console.log('----- Result ----');
  console.log(result);
})
.catch((err) => {
  console.error('Error', err);
});
