'use strict';

const bunyan = require('bunyan');
const log = bunyan.createLogger({ name: 'oictoolkit' });


class Logger {
  static getLogger() {
    return log;
  }
}

module.exports = Logger;
