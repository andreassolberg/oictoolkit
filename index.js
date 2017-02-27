'use strict';

const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const Dataporten = require('passport-dataporten');
const mustacheExpress = require('mustache-express');
const morgan = require('morgan');
const nconf = require('nconf');
// const fs = require('fs');

const App = require('./lib/App');
const Health = require('./lib/Health').Health;
// const MetadataStatement = require('./lib/MetadataStatement');

const app = express();

nconf.argv()
    .env()
    .file({ file: 'etc/config.json' })
    .defaults({
      http: {
        port: 8080,
        enforceHTTPS: false
      },
      dataporten: {
        enableAuthentication: false
      }
    });

const shouldRedirect = function (req) {
  if (req.headers['user-agent'] && req.headers['user-agent'].match(/GoogleHC/)) {
    return false;
  }
  if (!nconf.get('http:enforceHTTPS', false)) {
    return false;
  }
  if (req.protocol === 'https') {
    return false;
  }
  return true;
};

const dpsetup = new Dataporten.Setup(nconf.get('dataporten'));
const doAuth = nconf.get('dataporten:enableAuthentication');

app.set('json spaces', 2);
app.set('port', nconf.get('http:port'));
app.enable('trust proxy');

app.engine('mustache', mustacheExpress(__dirname + '/views/partials', '.mustache'));
app.set('view engine', 'mustache');
app.set('views', __dirname + '/views');
app.disable('view cache');

app.use(cookieParser());
app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(bodyParser.json());
app.use(session({
  secret: nconf.get('dataporten:sessionkey'),
  resave: false,
  saveUninitialized: false
}));

app.use(morgan('combined'));
app.use((req, res, next) => {
  if (shouldRedirect(req)) {
    return res.redirect('https://' + req.get('host') + req.originalUrl);
  }
  next();
});

if (doAuth) {
  app.use(dpsetup.passport.initialize());
  app.use(dpsetup.passport.session());

  dpsetup.setupAuthenticate(app, '/login');
  dpsetup.setupLogout(app, '/logout');
  dpsetup.setupCallback(app);

  // var authzConfig = {"redirectOnNoAccess": "/login"};
  // var aclSolberg = (new Dataporten.Authz(authzConfig))
  // .allowUsers(['9f70f418-3a75-4617-8375-883ab6c2b0af'])
  // .allowGroups(['fc:adhoc:892fe78e-14cd-43b1-abf8-b453a2c7758d'])
  // .middleware();

  app.use('/', Health);
  // app.use('/', aclSolberg);
}

app.use('/static/selectize', express.static('node_modules/selectize'));
app.use('/static/bootstrap-datepicker', express.static('node_modules/bootstrap-datepicker'));
app.use('/static/uninett-theme', express.static('node_modules/uninett-bootstrap-theme'));
app.use('/static/bootstrap', express.static('node_modules/bootstrap'));
app.use('/static/font-awesome', express.static('node_modules/font-awesome'));


const el = new App();
app.use('/', el.getRouter());
app.use('/', express.static('public'));

app.get('*', function(req, res) {
  res.status(404).send('404 Not found');
});


app.listen(app.get('port'), function() {
	console.log('Node app is running on port', app.get('port'));
});
