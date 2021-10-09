const axios = require('axios');
const ngrok = require("ngrok");
const base64url = require('base64url');
const crypto = require("crypto");
const jwt_decode = require('jwt-decode');
const canonicalize = require("canonicalize");
const qs = require("querystring");
const jwkThumbprint = require("jwk-thumbprint")


function publicKeyJwkToIonDid(publicKeyJwk) {
  const id = "signingKey";
  const contentBuffer = canonicalizeAsBuffer(publicKeyJwk);
  const intermediateHashBuffer = hashAsNonMultihashBuffer(contentBuffer);
  const multihashBuffer = multihash(intermediateHashBuffer);
  const commitment_hash = base64url(multihashBuffer);

  const patches = [
    {
      action: "replace",
      document: {
        publicKeys: [
          {
            id,
            type: "EcdsaSecp256k1VerificationKey2019",
            publicKeyJwk: publicKeyJwk,
            purposes: ["authentication", "assertionMethod"],
          },
        ],
      },
    },
  ];
  const delta = {
    updateCommitment: commitment_hash,
    patches,
  };
  const canonical_delta = canonicalizeAsBuffer({
    updateCommitment: commitment_hash,
    patches,
  });
  const deltaHash = base64url(multihash(canonical_delta));

  const suffixData = {
    deltaHash,
    recoveryCommitment: commitment_hash,
  };
  const canonicalizedStringBuffer = canonicalizeAsBuffer(
    suffixData
  );
  const multihashed = multihash(canonicalizedStringBuffer);
  const didUniqueSuffix = base64url(multihashed);
  const shortFormDid = `did:ion:${didUniqueSuffix}`;
  const initialState = {
    suffixData,
    delta,
  };
  const canonicalizedInitialStateBuffer = canonicalizeAsBuffer(
    initialState
  );
  const encodedCanonicalizedInitialStateString = base64url(
    canonicalizedInitialStateBuffer
  );
  const longFormDid = `${shortFormDid}:${encodedCanonicalizedInitialStateString}`;
  return longFormDid;
};

function privateKeyToJwk(privateKey) {
  const privateKeyBuffer = Buffer.from(privateKey, "hex");
  const ecdh = crypto.createECDH("secp256k1");
  ecdh.setPrivateKey(privateKeyBuffer);
  const pub = ecdh.getPublicKey();
  const publicKeyJwk = {
    kty: "EC",
    crv: "P-256K",
    x: base64url(pub.slice(1, 32 + 1)),
    y: base64url(pub.slice(32 + 1)),
  };
  const privateKeyJwk = {
    d: base64url(privateKeyBuffer),
    ...publicKeyJwk,
  };
  return { publicKeyJwk, privateKeyJwk };
};

function canonicalizeAsBuffer(content) {
  const canonicalizedString = canonicalize(content);
  const contentBuffer = Buffer.from(canonicalizedString);
  return contentBuffer;
}

function multihash(data) {
  const digest = crypto.createHash("sha256").update(data).digest();
  const prefix = Buffer.from([0x12, digest.length]);
  return Buffer.concat([prefix, digest]);
}

function privateKeyToPem(privateKey) {
  const asn1 = `302e0201010420${privateKey}${"a00706052b8104000a"}`;
  const asn1Base64 = Buffer.from(asn1, "hex").toString("base64");
  const pem = `${"-----BEGIN EC PRIVATE KEY-----\n"}${asn1Base64}${"\n-----END EC PRIVATE KEY-----"}`;
  return pem;
};

function sign(privateKey, header, payload) {
  const pem = privateKeyToPem(privateKey);
  const encodedHeader = base64url(JSON.stringify(header));
  const encodedPayload = base64url(JSON.stringify(payload));
  const message = `${encodedHeader}.${encodedPayload}`;
  const signature = base64url(
    crypto.createSign("sha256").update(message).sign(pem)
  );
  const result = `${encodedHeader}.${encodedPayload}.${signature}`;
  return result;
}

function hashAsNonMultihashBuffer(data) {
  const hash = crypto.createHash("sha256").update(data).digest();
  return hash;
};


function generateSub(myJwk) {
  console.log(myJwk)
  let jwktp = jwkThumbprint.jwkThumbprintByEncoding(myJwk, 'SHA-256', 'base64url');
  console.log(jwktp)
  return jwktp;
}

async function issue() {
  // let url = ngrok.getUrl();

  //=================================================================
  console.log("================ ISSUE ================")
  //=================================================================
  url = 'https://0955-49-106-211-205.ngrok.io';
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
  let state = decoded.state;
  let nonce = decoded.nonce;
  let manifest_url = decoded.presentation_definition.input_descriptors[0].issuance[0].manifest;
  let manifest_response = await axios.get(manifest_url);
  console.log(manifest_url)
  console.log(manifest_response.data)


  //=================================================================
  console.log("================ AUTHENTICATE ================")
  //=================================================================
  let idToken = manifest_response.data.input.attestations.idTokens[0];
  let client_id = idToken.client_id;
  let openIdConfigurationUri = idToken.configuration;

  let openIdConfigurationResponse = await axios.get(openIdConfigurationUri);
  const openIdConfiguration = openIdConfigurationResponse.data;
  const ranbomState = crypto.randomBytes(4).toString("hex");
  const codeVerifier =  crypto.randomBytes(44).toString("hex");
  const redirect_uri = `https://wallet.selmid.me/`;
  const codeChallenge = base64url(crypto.createHash("sha256").update(codeVerifier).digest()); 
  const authorizationUri = `${openIdConfiguration.authorization_endpoint}&redirect_uri=${redirect_uri}&client_id=${client_id}&response_type=code&scope=openid&state=${ranbomState}&code_challenge=${codeChallenge}&code_challenge_method=S256`;
  console.log(authorizationUri)


  //=================================================================
  console.log("================ PREPER SIOP ================")
  //=================================================================
  const privateKey = crypto.randomBytes(32).toString("hex");
  const { publicKeyJwk, privateKeyJwk } = privateKeyToJwk(privateKey);
  const did = publicKeyJwkToIonDid(publicKeyJwk);
  const jti = crypto.randomBytes(16).toString("hex");
  const header = {
    alg: "ES256K",
    kid: `${did}#${"signingKey"}`,
  };
  const payload = {
    iss: "https://self-issued.me",
    iat: 0,
    exp: 9999999999,
    did,
    jti,
    nonce,
    state,
    sub_jwk: publicKeyJwk,
    sub: generateSub(publicKeyJwk),
    aud: redirect_uri,
  };
  let selfIssuedIdToken = sign(privateKey, header, payload);

  //=================================================================
  console.log("================ SIOP ================")
  //=================================================================
  await axios.post(
    redirect_uri,
    qs.stringify({
      id_token: selfIssuedIdToken,
      state,
    }),
    {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    }
  )
    .then(res => console.log(res))
    .catch(err => console.log(err))
};



issue();