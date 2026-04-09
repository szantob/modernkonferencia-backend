import type { Route } from "./+types/keygen";
import crypto from "crypto";

const PRIVATE_KEY = process.env.RSA_PRIVATE_KEY || `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...
-----END PRIVATE KEY-----`;

function encryptToken(baseText: string = "entrypass", incrementalNumber: number = 1): string {
	try {
		// Format: "entrypass00000001"
		const formattedNumber = String(incrementalNumber).padStart(8, "0");
		const plainToken = `${baseText}${formattedNumber}`;

		// Encrypt using RSA private key
		const encrypted = crypto.privateEncrypt(
			{
				key: PRIVATE_KEY,
				padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
			},
			Buffer.from(plainToken)
		);

		// Return as base64
		return encrypted.toString("base64");
	} catch (error) {
		throw new Error("Failed to encrypt token");
	}
}

export function meta({}: Route.MetaArgs) {
	return [
		{ title: "Token Generator" },
		{ name: "description", content: "Generate encrypted access tokens" },
	];
}

export async function loader({ request }: Route.LoaderArgs) {
	// Only allow POST requests or GET with query parameters
	if (request.method === "GET") {
		const url = new URL(request.url);
		const baseText = url.searchParams.get("base") || "entrypass";
		const incrementalNumber = parseInt(url.searchParams.get("number") || "1", 10);

		// Validate inputs
		if (incrementalNumber < 0 || incrementalNumber > 99999999) {
			return new Response(
				JSON.stringify({ error: "Number must be between 0 and 99999999" }),
				{
					status: 400,
					headers: { "Content-Type": "application/json" },
				}
			);
		}

		try {
			const encryptedToken = encryptToken(baseText, incrementalNumber);
			return new Response(
				JSON.stringify({
					plainText: `${baseText}${String(incrementalNumber).padStart(8, "0")}`,
					encrypted: encryptedToken,
					url: `/?token=${encryptedToken}`,
				}),
				{
					status: 200,
					headers: { "Content-Type": "application/json" },
				}
			);
		} catch (error) {
			return new Response(
				JSON.stringify({ error: "Failed to generate token" }),
				{
					status: 500,
					headers: { "Content-Type": "application/json" },
				}
			);
		}
	}

	if (request.method === "POST") {
		try {
			const body = await request.json();
			const baseText = body.base || "entrypass";
			const incrementalNumber = parseInt(body.number || "1", 10);

			// Validate inputs
			if (incrementalNumber < 0 || incrementalNumber > 99999999) {
				return new Response(
					JSON.stringify({ error: "Number must be between 0 and 99999999" }),
					{
						status: 400,
						headers: { "Content-Type": "application/json" },
					}
				);
			}

			const encryptedToken = encryptToken(baseText, incrementalNumber);
			return new Response(
				JSON.stringify({
					plainText: `${baseText}${String(incrementalNumber).padStart(8, "0")}`,
					encrypted: encryptedToken,
					url: `/?token=${encryptedToken}`,
				}),
				{
					status: 200,
					headers: { "Content-Type": "application/json" },
				}
			);
		} catch (error) {
			return new Response(
				JSON.stringify({ error: "Failed to generate token" }),
				{
					status: 500,
					headers: { "Content-Type": "application/json" },
				}
			);
		}
	}

	return new Response("Method Not Allowed", { status: 405 });
}

export default function KeyGen() {
	return (
		<div style={{ padding: "20px", fontFamily: "monospace" }}>
			<h1>Token Generator</h1>
			<p>Generate encrypted access tokens for your application</p>

			<section style={{ marginBottom: "30px" }}>
				<h2>Using GET Request:</h2>
				<pre>/keygen?base=entrypass&number=1</pre>
				<p>Parameters:</p>
				<ul>
					<li><strong>base</strong>: Base text (default: "entrypass")</li>
					<li><strong>number</strong>: Incremental number 0-99999999 (default: 1)</li>
				</ul>
			</section>

			<section style={{ marginBottom: "30px" }}>
				<h2>Using POST Request:</h2>
				<pre>
					{`curl -X POST http://localhost:3000/keygen \\
  -H "Content-Type: application/json" \\
  -d '{"base":"entrypass","number":1}'`}
				</pre>
			</section>

			<section>
				<h2>Response Example:</h2>
				<pre>
					{`{
  "plainText": "entrypass00000001",
  "encrypted": "base64encodedEncryptedToken...",
  "url": "/?token=base64encodedEncryptedToken..."
}`}
				</pre>
			</section>

			<section style={{ marginTop: "30px", padding: "10px", backgroundColor: "#f0f0f0" }}>
				<h3>Quick Examples:</h3>
				<ul>
					<li><a href="/keygen?base=entrypass&number=1">/keygen?base=entrypass&number=1</a></li>
					<li><a href="/keygen?base=entrypass&number=100">/keygen?base=entrypass&number=100</a></li>
					<li><a href="/keygen?base=entrypass&number=999">/keygen?base=entrypass&number=999</a></li>
				</ul>
			</section>
		</div>
	);
}
