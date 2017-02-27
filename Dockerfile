FROM node:argon

RUN mkdir -p /app
WORKDIR /app

# Install app dependencies
COPY package.json /app/
RUN npm install

RUN curl -o /app/node_modules/uninett-bootstrap-theme/fonts/colfaxLight.woff http://mal.uninett.no/uninett-theme/fonts/colfaxLight.woff
RUN curl -o /app/node_modules/uninett-bootstrap-theme/fonts/colfaxMedium.woff http://mal.uninett.no/uninett-theme/fonts/colfaxMedium.woff
RUN curl -o /app/node_modules/uninett-bootstrap-theme/fonts/colfaxRegular.woff http://mal.uninett.no/uninett-theme/fonts/colfaxRegular.woff
RUN curl -o /app/node_modules/uninett-bootstrap-theme/fonts/colfaxThin.woff http://mal.uninett.no/uninett-theme/fonts/colfaxThin.woff
RUN curl -o /app/node_modules/uninett-bootstrap-theme/fonts/colfaxRegularItalic.woff http://mal.uninett.no/uninett-theme/fonts/colfaxRegularItalic.woff

COPY . /app
EXPOSE 8080

CMD ["npm", "start"]
