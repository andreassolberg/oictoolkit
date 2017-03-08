'use strict';

class SignatureValidationException extends Error {

  constructor(message) {
    super(message);
  }

  setError(err) {
    if (err.message) {
      // eslint-disable-next-line prefer-template
      this.message += ' ' + err.message;
    }
    if (err.stack) {
      this.stack = err.stack;
    }
  }

  setContext(c) {
    this.errorContext = c;
  }

  getErrorContextView() {
    const view = {
      title: this.message,
      entries: [],
    };
    if (this.errorContext) {

      for (const key in this.errorContext) {
        if (this.errorContext.hasOwnProperty(key)) {
          const entry = {
            title: key
          };
          if (typeof this.errorContext[key] === 'string') {
            entry.value = this.errorContext[key];
          } else {
            entry.value = JSON.stringify(this.errorContext[key], undefined, 2);
          }
          view.entries.push(entry);
        }
      }
    }
    console.log(view);
    return view;

  }

}

module.exports = SignatureValidationException;
