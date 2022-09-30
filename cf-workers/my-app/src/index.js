import { Router } from 'itty-router';

const router = Router();
const jwkSingle = {
  kty: "oct",
  alg: "HS256",
  kid: envVar_jwkUUID,
  k: envVar_jwkKey,
};


// index page for health check
router.get("/", () => {
  return new Response("Hello, This page is intended to leave for blank.")
});

// show verification captcha page
router.get("/show" + urlPrefix + "/:uuid/:userid/:expt", ({ params }) => {
  // Decode text like "Hello%20world" into "Hello world"
  let verifySessionUUID = params.uuid;
  let verifyPage = `
  <html lang="zh-CN">
    <head>
        <meta charset="utf-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Verification</title>
        <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
    </head>
    <body>
        <h1>Please complete CAPTCHA. Wait for 2-5 seconds, If you see nothing, just click submit.</h1>
        <h2>Powered by Cloudflare</h2>
        <form action="/verify${urlPrefix}/u?uuid=${verifySessionUUID}&userid=${params.userid}&expt=${params.expt}" method="post">
          <div class="cf-turnstile" data-sitekey="${capt_sitekey}" data-callback="javascriptCallback"></div>
          <input type="hidden" name="_uuid" value="${verifySessionUUID}">
          <br />
          <input type="submit" value="Submit">
        </form>
    </body>
  </html>
  `;
  // Return the HTML with the string to the client
  return new Response(verifyPage, {
    headers: {
      "Content-Type": "text/html"
    }
  })
});

async function callServerSideVerify(token, uip) {
  const SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
  try {
    // Turnstile injects a token in "cf-turnstile-response".
    // Validate the token by calling the "/siteverify" API endpoint.
    let formData = new FormData();
    formData.append('secret', capt_sitesecret);
    formData.append('response', token);
    formData.append('remoteip', uip);

    const resp = await fetch(SITEVERIFY_URL, {
      body: formData,
      method: 'POST',
    });

    const json = await resp.json();
    return json;
  } catch {
    return { success: false, error: "Failed to call server side verify" };
  };
}

function _arrayBufferToBase64( buffer ) {
  var binary = '';
  var bytes = new Uint8Array( buffer );
  var len = bytes.byteLength;
  for (var i = 0; i < len; i++) {
      binary += String.fromCharCode( bytes[ i ] );
  }
  return btoa( binary );
}

// server side verify check.
router.post("/verify" + urlPrefix + "/u", async request => {
  const contentType = request.headers.get("Content-Type")
  if (contentType.includes("form")) {
    // This is a form request.
    const formData = await request.formData();
    const userID = request.query.userid;
    const paramUUID = request.query.uuid;
    const timeStamp = request.query.expt;
    const sessionUUID = formData.get("_uuid");
    const userIP = request.headers.get('CF-Connecting-IP');
    if (sessionUUID === paramUUID) {
      var res = await callServerSideVerify(formData.get("cf-turnstile-response"), userIP);
      if (res.success === true){
        const jwkSigKey = await crypto.subtle.importKey(
          "jwk", jwkSingle, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]
        );
        let sigFinal = await crypto.subtle.sign(
          "HMAC",
          jwkSigKey,
          new TextEncoder().encode(sessionUUID + "/" + userID + "/" + timeStamp)
        );
        let sigBase64 = _arrayBufferToBase64(sigFinal);
        return new Response(`Send <br /> <pre>${sigBase64}</pre> back to chat conversation to finish your verification.`, {
          headers: { "Content-Type": "text/html" },
          status: 200,
        })
      } else {
        return new Response("failed to verify", {
          status: 403,
        });
      }
    } else {
      return new Response("400 Invalid Request", {
        status: 400,
        headers: { "Content-Type": "text/plain", "d": "1" }
      })
    }
  } else {
    return new Response("400 Invalid Request", {
      headers: { "Content-Type": "text/plain", "d": "2" },
      status: 400
    })
  }
});

/*
This is the last route we define, it will match anything that hasn't hit a route we've defined
above, therefore it's useful as a 404 (and avoids us hitting worker exceptions, so make sure to include it!).

Visit any page that doesn't exist (e.g. /foobar) to see it in action.
*/
router.all("*", () => new Response("404, not found!", { status: 404 }));

/*
This snippet ties our worker to the router we deifned above, all incoming requests
are passed to the router where your routes are called and the response is sent.
*/
addEventListener('fetch', (e) => {
  e.respondWith(router.handle(e.request))
})