const axios = require('axios');
const ngrok = require("ngrok");
const base64url = require('base64url');
const crypto = require("crypto");
const jwt_decode = require('jwt-decode');

async function issue() {
  // let url = ngrok.getUrl();
  url = '';
  console.log(url)
  let response = await axios.get(url+'/issue-request');
  console.log(response)
  let url_strs = response.data.split('?request_uri=');
  let redirect_url = url_strs[1].replace('%3A%2F%2F', '://').replace('%2F', '/').replace('%3F', '?').replace('%3D', '=');
  console.log('========================')
  console.log(redirect_url)
  console.log('========================')
  let jwt_response = await axios.get(redirect_url);
  let decoded = jwt_decode(jwt_response.data);
  console.log(decoded.presentation_definition.input_descriptors[0].issuance[0].manifest)
  console.log(decoded)
  let manifest_url = decoded.presentation_definition.input_descriptors[0].issuance[0].manifest;
  let manifest_response = await axios.get(manifest_url);
  console.log(manifest_url)
  console.log(manifest_response.data)

  let idToken = manifest_response.data.input.attestations.idTokens[0];
  let client_id = idToken.client_id;
  let openIdConfigurationUri = idToken.configuration;

  let openIdConfigurationResponse = await axios.get(openIdConfigurationUri);
  const openIdConfiguration = openIdConfigurationResponse.data;
  const ranbomState = generateState();
  const codeVerifier = generateVerifier();
  const redirect_uri = `https://wallet.selmid.me/`;
  const codeChallenge = generateHash("sha256", codeVerifier);
  const authorizationUri = `${openIdConfiguration.authorization_endpoint}&redirect_uri=${redirect_uri}&client_id=${client_id}&response_type=code&scope=openid&state=${ranbomState}&code_challenge=${codeChallenge}&code_challenge_method=S256`;
  console.log(authorizationUri)
};


const generateState = () => {
  return crypto.randomBytes(4).toString("hex");
};

const generateVerifier = () => {
  return crypto.randomBytes(44).toString("hex");
};

const generateHash = (type, data) => {
  return base64url(crypto.createHash(type).update(data).digest());
};

issue();