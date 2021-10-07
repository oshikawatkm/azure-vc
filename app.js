const express = require('express');
const ngrok = require("ngrok");
const axios = require("axios");
const session = require('express-session')
const bodyParser = require('body-parser');
const base64url = require('base64url')
const secureRandom = require('secure-random');
const dotenv = require('dotenv');
const cors = require('cors');
const { ClientSecretCredential } = require('@azure/identity');
const  { CryptoBuilder, 
      LongFormDid, 
      RequestorBuilder,
      KeyReference,
      KeyUse
    } = require('verifiablecredentials-verification-sdk-typescript');
const config = require('./config/ion.json');
dotenv.config({ path: './.env' });

const kvCredentials = new ClientSecretCredential(config.azTenantId, config.azClientId, config.azClientSecret);
const signingKeyReference = new KeyReference(config.kvSigningKeyId, 'key', config.kvRemoteSigningKeyId);

let crypto = new CryptoBuilder()
    .useSigningKeyReference(signingKeyReference)
    .useKeyVault(kvCredentials, config.kvVaultUri)
    .useDid(config.did)
    .build();

const app = express()
app.use(cors())

app.use(express.static('public'))

let sessionStore = new session.MemoryStore();
app.use(session({
  secret: 'cookie-secret-key',
  resave: false,
  saveUninitialized: true,
  store: sessionStore
}))
let parser = bodyParser.urlencoded({ extended: false });

app.get("/echo",
    function (req, res) {
        res.status(200).json({
            'date': new Date().toISOString(),
            'api': req.protocol + '://' + req.hostname + req.originalUrl,
            'Host': req.hostname,
            'x-forwarded-for': req.headers['x-forwarded-for'],
            'x-original-host': req.headers['x-original-host'],
            'issuerDid': config.did,
            'credentialType': config.credentialType,
            'credential': config.credential
            });
    }
);

app.get('/issue-request', async (req, res) => {
  state = req.session.id;
  const nonce = base64url.encode(Buffer.from(secureRandom.randomUint8Array(10)));
  const requestBuilder = new RequestorBuilder({
    presentationDefinition: {
      input_descriptors: [
        {
          id: "expert",
          schema: {
            uri: config.credentialType,
          },
          issuance: [
            {
              manifest: config.credential
            }
          ]
        }
      ]
    }
  }, crypto).allowIssuance()
  .useNonce(nonce)
  .useState(state);

  req.session.issueRequest = await requestBuilder.build().create();
  
  let requestUri = encodeURIComponent(`https://${req.hostname}/issue-request.jwt?id=${req.session.id}`);
  let issueRequestReference = `https://${req.hostname}/?request_uri=` + requestUri;
  res.send(issueRequestReference)
})

app.get('/issue-request.jwt', async (req, res) => {
  console.log(req.params)
  console.log('========================')
  console.log(session)
  console.log('========================')
  sessionStore.get(req.query.id, (error, session) => {
    res.send(session.issueRequest.request);
  })
})

app.get('/presentation-request', async (req, res) => {
  const nonce = base64url.encode(Buffer.from(secureRandom.randomUint8Array(10)));
  const clientId = `https://${req.hostname}/presentation-response`;

  const requestBuilder = new RequestorBuilder({
    clientName: client.client_name,
    clientId: clientId,
    redirectUri: clientId,
    logoUri: client.logo_uri,
    tosUri: client.tos_uri,
    client_purpose: client.client_purpose,
    presentationDefinition: {
      input_descriptors: [{
          id:"expert",
          schema: {
              uri: [config.credentialType],
          },
          issuance: [{
              manifest: config.credential
          }]
      }]
  }
},  crypto)
    .useNonce(nonce)
    .useState(state);

  req.session.presentationRequest = await requestBuilder.build().create();
  let requestUri = encodeURIComponent(`https://${req.hostname}/presentation-request.jwt?id=${req.session.id}`);
  let presentationRequestReference = 'openid://vc/?request_uri=' + requestUri;
  res.send(presentationRequestReference);
})


app.get('/presentation-request.jwt', async (req, res) => {
  sessionStore.get(req.query.id, (error, session) => {
    if (error || !session) {
        res.status(404).send({ 'error': 'session not found' }).end();
    } else {
      res.send(session.presentationRequest.request);
    }
  });
})


app.post('/presentation-response', parser, async (req, res) => {
  const clientId = `https://${req.hostname}/presentation-response`

  const validator = new ValidatorBuilder(crypto)
    .useTrustedIssuersForVerifiableCredentials({[credentialType]: issuerDid})
    .useAudienceUrl(clientId)
    .build();

  const token = req.body.id_token;
  const validationResponse = await validator.validate(req.body.id_token);
  
  if (!validationResponse.result) {
      console.error(`Validation failed: ${validationResponse.detailedError}`);
      return res.send()
  }

  let verifiedCredential = validationResponse.validationResult.verifiableCredentials[credentialType].decodedToken;
  console.log(`${verifiedCredential.vc.credentialSubject.firstName} ${verifiedCredential.vc.credentialSubject.lastName} is a Verified Credential Expert!`);

  sessionStore.get(req.body.state, (error, session) => {
    session.verifiedCredential = verifiedCredential;
    sessionStore.set(req.body.state, session, (error) => {
      res.send();
    });
  })
})

app.get('/presentation-response', async (req, res) => {
  if (req.session.verifiedCredential) {

    presentedCredential = req.session.verifiedCredential;
    req.session.verifiedCredential = null;
    return res.send(`Congratulations, ${presentedCredential.vc.credentialSubject.firstName} ${presentedCredential.vc.credentialSubject.lastName} is a Verified Credential Expert!`)  
  }

  res.send('')
})

const port = process.env.PORT || 3000;

ngrok.connect(port).then((url) => {
  app.listen(port, () => {
    console.log(`Example issuer app listening on port ${port}!`)
    console.log(`Example app listening at ${url}`);
  })

});