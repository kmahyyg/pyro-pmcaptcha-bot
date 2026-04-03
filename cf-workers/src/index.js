import { Router } from "itty-router";

const router = Router();

const HTML_HEADERS = {
	"content-type": "text/html; charset=utf-8",
	"cache-control": "no-store",
};

// default verification ttl is always 5 minutes, add a 30s jitter to account for clock skew and network delays, etc.
const REQUEST_TS_MAX_AGE_SECONDS = 330;

function base64UrlEncodeBytes(bytes) {
	let binary = "";
	for (const b of bytes) binary += String.fromCharCode(b);
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlEncodeText(text) {
	return base64UrlEncodeBytes(new TextEncoder().encode(text));
}

function base64UrlDecodeBytes(text) {
	const padded = text + "=".repeat((4 - (text.length % 4)) % 4);
	const normalized = padded.replace(/-/g, "+").replace(/_/g, "/");
	const binary = atob(normalized);
	const out = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
	return out;
}

function htmlEscape(value) {
	return String(value)
		.replaceAll("&", "&amp;")
		.replaceAll("<", "&lt;")
		.replaceAll(">", "&gt;")
		.replaceAll('"', "&quot;")
		.replaceAll("'", "&#39;");
}

function isValidSession(sessionId) {
	return /^[0-9a-fA-F-]{32,40}$/.test(sessionId);
}

function isValidTelegramUserId(userId) {
	return /^\d{5,20}$/.test(userId);
}

function isValidTimestamp(ts) {
	return /^\d{10,13}$/.test(ts);
}

function isTimestampFresh(tsText) {
	if (!isValidTimestamp(tsText)) return false;
	const ts = Number(tsText);
	if (!Number.isFinite(ts)) return false;
	const now = Math.floor(Date.now() / 1000);
	return Math.abs(now - ts) <= REQUEST_TS_MAX_AGE_SECONDS;
}

async function importHmacKeyJwk(envVar_jwkUUID, envVar_jwkKey) {
	const jwkSingle = {
		kty: "oct",
		alg: "HS256",
		kid: envVar_jwkUUID,
		k: envVar_jwkKey,
	};
	return crypto.subtle.importKey(
		"jwk",
		jwkSingle,
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign","verify"]
	);
}

async function signPayload(key, payload) {
	const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
	return base64UrlEncodeBytes(new Uint8Array(sig));
}

function renderPage({
	siteKey,
	postPath,
	sessionId,
	userId,
	requestTs,
	outputToken = "",
	error = "",
	showVerifyForm = true,
}) {
	const escapedSession = htmlEscape(sessionId || "");
	const escapedUserId = htmlEscape(userId || "");
	const escapedRequestTs = htmlEscape(requestTs || "");
	const escapedToken = htmlEscape(outputToken || "");
	const escapedError = htmlEscape(error || "");

	return `<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8" />
	<meta name="viewport" content="width=device-width, initial-scale=1" />
	<title>Telegram PM Verify</title>
	<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
	<style>
		:root {
			--bg: #f8f5eb;
			--panel: #fffdf7;
			--ink: #22201f;
			--muted: #746c63;
			--line: #d8cfbe;
			--accent: #0d9488;
			--accent2: #f59e0b;
		}
		* { box-sizing: border-box; }
		body {
			margin: 0;
			color: var(--ink);
			background:
				radial-gradient(60rem 30rem at 110% -10%, #fed7aa 0%, transparent 60%),
				radial-gradient(50rem 26rem at -10% 110%, #99f6e4 0%, transparent 60%),
				var(--bg);
			font-family: ui-serif, Georgia, Cambria, "Times New Roman", serif;
			min-height: 100vh;
			display: grid;
			place-items: center;
			padding: 1rem;
		}
		.card {
			width: min(720px, 100%);
			background: var(--panel);
			border: 1px solid var(--line);
			border-radius: 14px;
			padding: 1rem 1.1rem;
			box-shadow: 0 15px 40px rgba(34, 32, 31, 0.08);
		}
		h1 {
			margin: 0 0 0.5rem;
			font-size: 1.4rem;
			letter-spacing: 0.01em;
		}
		p {
			margin: 0.2rem 0 0.9rem;
			color: var(--muted);
			line-height: 1.35;
		}
		.meta {
			border: 1px dashed var(--line);
			background: #fff;
			border-radius: 10px;
			padding: 0.65rem 0.75rem;
			margin-bottom: 0.9rem;
			font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
			font-size: 0.86rem;
			line-height: 1.4;
			overflow-wrap: anywhere;
		}
		.err {
			border: 1px solid #fca5a5;
			background: #fef2f2;
			color: #991b1b;
			border-radius: 10px;
			padding: 0.65rem 0.75rem;
			margin-bottom: 0.9rem;
			font-size: 0.92rem;
		}
		.row {
			display: flex;
			flex-wrap: wrap;
			gap: 0.7rem;
			margin: 0.9rem 0;
			align-items: center;
		}
		button {
			border: 0;
			border-radius: 9px;
			padding: 0.6rem 0.95rem;
			background: linear-gradient(135deg, var(--accent) 0%, #0f766e 100%);
			color: #fff;
			font-weight: 700;
			cursor: pointer;
		}
		button:hover { filter: brightness(1.03); }
		textarea {
			width: 100%;
			min-height: 160px;
			border-radius: 10px;
			border: 1px solid var(--line);
			background: #fff;
			padding: 0.7rem;
			font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
			font-size: 0.85rem;
			line-height: 1.35;
			resize: vertical;
		}
		.hint {
			margin-top: 0.7rem;
			font-size: 0.9rem;
		}
		.hint code {
			display: block;
			max-width: 100%;
			background: #f4efe2;
			border: 1px solid var(--line);
			border-radius: 6px;
			padding: 0.35rem 0.45rem;
			overflow-wrap: anywhere;
			word-break: break-word;
			white-space: pre-wrap;
		}
		@media (max-width: 560px) {
			.card { padding: 0.85rem; }
			h1 { font-size: 1.25rem; }
			.cf-turnstile { transform-origin: left top; }
		}
	</style>
</head>
<body>
	<main class="card">
		<h1>Telegram PM Verification</h1>
		<p>Complete the captcha, then copy your token and send it back to Telegram.</p>
		<div class="meta">Telegram User ID: ${escapedUserId}</div>
		${escapedError ? `<div class="err">${escapedError}</div>` : ""}
		${showVerifyForm ? `<form method="post" action="${htmlEscape(postPath)}">
			<div class="row">
				<div class="cf-turnstile" data-sitekey="${htmlEscape(siteKey)}" data-theme="light"></div>
				<button type="submit">Verify and Generate Token</button>
			</div>
		</form>` : ""}
		<textarea readonly placeholder="Token appears here after successful verification">${escapedToken}</textarea>
		${escapedToken ? `<p class="hint">Send this command in Telegram: <code>/verify ${escapedToken}</code></p>` : ""}
	</main>
</body>
</html>`;
}

async function verifyTurnstile({ secret, token, remoteip }) {
	const payload = new URLSearchParams();
	payload.set("secret", secret);
	payload.set("response", token);
	if (remoteip) payload.set("remoteip", remoteip);

	const resp = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
		method: "POST",
		body: payload,
	});

	if (!resp.ok) {
		return { success: false, errors: ["siteverify_http_error"] };
	}
	return resp.json();
}

router.get("/show:prefix/:uuid/:userid/:currentTimestamp", async (request, env) => {
	if (request.params.prefix !== env.urlPrefix) {
		return new Response("Not Found", { status: 404 });
	}

	const sessionId = request.params.uuid || "";
	const userId = request.params.userid || "";
	const currentTimestamp = request.params.currentTimestamp || "";
	if (!isValidSession(sessionId) || !isValidTelegramUserId(userId) || !isValidTimestamp(currentTimestamp)) {
		return new Response("Invalid URL parameters", { status: 400 });
	}
	if (!isTimestampFresh(currentTimestamp)) {
		const expiredPage = renderPage({
			siteKey: env.capt_sitekey,
			postPath: `/show${env.urlPrefix}/${sessionId}/${userId}/${currentTimestamp}`,
			sessionId,
			userId,
			requestTs: currentTimestamp,
			error: "Verification failed: request expired.",
			showVerifyForm: false,
		});
		return new Response(expiredPage, { status: 410, headers: HTML_HEADERS });
	}

	const page = renderPage({
		siteKey: env.capt_sitekey,
		postPath: `/show${env.urlPrefix}/${sessionId}/${userId}/${currentTimestamp}`,
		sessionId,
		userId,
		requestTs: currentTimestamp,
	});
	return new Response(page, { status: 200, headers: HTML_HEADERS });
});

router.post("/show:prefix/:uuid/:userid/:currentTimestamp", async (request, env) => {
	if (request.params.prefix !== env.urlPrefix) {
		return new Response("Not Found", { status: 404 });
	}

	const sessionId = String(request.params.uuid || "").trim();
	const userId = String(request.params.userid || "").trim();
	const currentTimestamp = String(request.params.currentTimestamp || "").trim();
	const body = await request.formData();
	const turnstileToken = String(body.get("cf-turnstile-response") || "").trim();

	const postPath = `/show${env.urlPrefix}/${sessionId}/${userId}/${currentTimestamp}`;

	if (!isValidSession(sessionId) || !isValidTelegramUserId(userId) || !isValidTimestamp(currentTimestamp)) {
		const invalidPage = renderPage({
			siteKey: env.capt_sitekey,
			postPath,
			sessionId,
			userId,
			requestTs: currentTimestamp,
			error: "Invalid session or user id.",
		});
		return new Response(invalidPage, { status: 400, headers: HTML_HEADERS });
	}
	if (!isTimestampFresh(currentTimestamp)) {
		const expiredPage = renderPage({
			siteKey: env.capt_sitekey,
			postPath,
			sessionId,
			userId,
			requestTs: currentTimestamp,
			error: "Verification failed: request expired.",
			showVerifyForm: false,
		});
		return new Response(expiredPage, { status: 410, headers: HTML_HEADERS });
	}

	if (!turnstileToken) {
		const missingCaptcha = renderPage({
			siteKey: env.capt_sitekey,
			postPath,
			sessionId,
			userId,
			requestTs: currentTimestamp,
			error: "Captcha token is missing. Please try again.",
		});
		return new Response(missingCaptcha, { status: 400, headers: HTML_HEADERS });
	}

	const verifyResult = await verifyTurnstile({
		secret: env.capt_sitesecret,
		token: turnstileToken,
		remoteip: request.headers.get("CF-Connecting-IP") || "",
	});

	if (!verifyResult.success) {
		const verifyError = renderPage({
			siteKey: env.capt_sitekey,
			postPath,
			sessionId,
			userId,
			requestTs: currentTimestamp,
			error: `Captcha verification failed: ${(verifyResult["error-codes"] || verifyResult.errors || ["unknown_error"]).join(", ")}`,
		});
		return new Response(verifyError, { status: 403, headers: HTML_HEADERS });
	}

	const issuedAt = Math.floor(Date.now() / 1000);
	const payload = `${sessionId}/${userId}/${issuedAt}`;

	const hmacKey = await importHmacKeyJwk(env.envVar_jwkUUID, env.envVar_jwkKey);
	const sigB64Url = await signPayload(hmacKey, payload);
	const output = base64UrlEncodeText(`${payload}/${sigB64Url}`);

	const resultPage = renderPage({
		siteKey: env.capt_sitekey,
		postPath,
		sessionId,
		userId,
		requestTs: currentTimestamp,
		outputToken: output,
	});
	return new Response(resultPage, { status: 200, headers: HTML_HEADERS });
});

router.get("/", () => {
	return new Response("Telegram PM verification worker is online.", { status: 200 });
});

router.all("*", () => new Response("Not Found", { status: 404 }));

export default {
	fetch(request, env, ctx) {
		return router.fetch(request, env, ctx);
	},
};
