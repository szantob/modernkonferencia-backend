import type { Route } from "./+types/keygen";

const PRIVATE_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQCSZdW0UjnXLENtH/6/nXiWuDtmGK/dGIp9d06cEHK8LsUBvKUq
YvUlD5kMQEYZitu+K5Hl3rBj24gUbEYcoNOaMEd3PLW5sH0kEjZGMWAF5vKSXzW2
qzAKvRujW3nGcTvvBgES+VDnlMHbTMQWvN6J8D4XLGfwQaLWeEbngeq3pQIDAQAB
AoGBAIz0yh/V7+UStFUUslbSivIrrt1ttZ6e63FEd4bie2ZfbcZvWWQHZdvqOcVG
+XfMcCmZj9+RW6q6DDsFyTf1Tea53HZgU+P0XxSDj4HK2HrQ93umy7JhUbq3Ap9B
vkntxEJzyRszaR9sDX86HEozOTYg8EL4B1F7N9lf+xBE8Ho9AkEAxpI6yltV4ueb
hiOoD6SFCvBrTLFn0Bk3yZ2tUb8lHkRiA4HD34SNkKQDCIE4JfjdAVPKt3wQ4027
8T5KH2ICowJBALy8zSsdh6MrDNKZbQlmzY0HoZBXyCjhpytPjmFnAkUHzV6gC30t
SjvSyx6aJngVKkoeaTpK7Po9u6OnZ370SRcCQQC1WJ6wZ7GMRBDY9H9rqciHMQIN
TIeOmTlFu+apnXN8rN8GbOBBpYDT87WBcuGgbCMKL0gXQgr6S+e0bjqrZosZAkB4
nIrch7V7P3KlTujQPkMTYhIMZRyDi5jB48hQVHyt0ouacdqFtyCeVFn7h3UX/iaV
URPb7a+9RyAXOE66YbAnAkEAkmowqlMfEoxGVObW2c0yS90M0GSrFelsz7qmPhe+
6U0Q8+vUKNBOJ5jc1h2MHAqhT3P6ulSST8ApOyFpnyVyKQ==
-----END RSA PRIVATE KEY-----`;

function pemToArrayBuffer(pem: string): Uint8Array {
	const b64 = pem
		.replace(/-----BEGIN [\w\s]+-----/, "")
		.replace(/-----END [\w\s]+-----/, "")
		.replace(/\s/g, "");
	const binary = atob(b64);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes;
}

function encodeDerLength(tag: number, length: number): Uint8Array {
	if (length < 0x80) {
		return new Uint8Array([tag, length]);
	} else if (length < 0x100) {
		return new Uint8Array([tag, 0x81, length]);
	} else {
		return new Uint8Array([tag, 0x82, (length >> 8) & 0xff, length & 0xff]);
	}
}

function pkcs1ToPkcs8(pkcs1Bytes: Uint8Array): Uint8Array {
	// AlgorithmIdentifier: SEQUENCE { OID rsaEncryption (1.2.840.113549.1.1.1), NULL }
	const algorithmIdentifier = new Uint8Array([
		0x30, 0x0d,
		0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
		0x05, 0x00,
	]);
	// Version INTEGER { 0 }
	const version = new Uint8Array([0x02, 0x01, 0x00]);
	// OCTET STRING containing the PKCS#1 bytes
	const octetStringHeader = encodeDerLength(0x04, pkcs1Bytes.length);
	const innerLength =
		version.length + algorithmIdentifier.length + octetStringHeader.length + pkcs1Bytes.length;
	const outerHeader = encodeDerLength(0x30, innerLength);

	const pkcs8 = new Uint8Array(outerHeader.length + innerLength);
	let offset = 0;
	pkcs8.set(outerHeader, offset); offset += outerHeader.length;
	pkcs8.set(version, offset); offset += version.length;
	pkcs8.set(algorithmIdentifier, offset); offset += algorithmIdentifier.length;
	pkcs8.set(octetStringHeader, offset); offset += octetStringHeader.length;
	pkcs8.set(pkcs1Bytes, offset);
	return pkcs8;
}

async function encryptToken(baseText: string = "entrypass", incrementalNumber: number = 1): Promise<string> {
	// Format: "entrypass00000001"
	const formattedNumber = String(incrementalNumber).padStart(8, "0");
	const plainToken = `${baseText}${formattedNumber}`;

	const pkcs1Bytes = pemToArrayBuffer(PRIVATE_KEY);
	const pkcs8Bytes = pkcs1ToPkcs8(pkcs1Bytes);

	const privateKey = await crypto.subtle.importKey(
		"pkcs8",
		pkcs8Bytes,
		{ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
		false,
		["sign"]
	);

	const encodedData = new TextEncoder().encode(plainToken);
	const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", privateKey, encodedData);

	return btoa(Array.from(new Uint8Array(signature), (b) => String.fromCharCode(b)).join(""));
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
		const baseParam = url.searchParams.get("base");
		const numberParam = url.searchParams.get("number");

		// No query params — render documentation page
		if (baseParam === null && numberParam === null) {
			return null;
		}

		const baseText = baseParam ?? "entrypass";
		const incrementalNumber = parseInt(numberParam ?? "1", 10);

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
			const encryptedToken = await encryptToken(baseText, incrementalNumber);
			return {
				plainText: `${baseText}${String(incrementalNumber).padStart(8, "0")}`,
				encrypted: encryptedToken,
				url: `/?token=${encodeURIComponent(encryptedToken)}&id=${encodeURIComponent(`${baseText}${String(incrementalNumber).padStart(8, "0")}`)}`,
			};
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

			const encryptedToken = await encryptToken(baseText, incrementalNumber);
			return new Response(
				JSON.stringify({
					plainText: `${baseText}${String(incrementalNumber).padStart(8, "0")}`,
					encrypted: encryptedToken,
					url: `/?token=${encodeURIComponent(encryptedToken)}&id=${encodeURIComponent(`${baseText}${String(incrementalNumber).padStart(8, "0")}`)}`,
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

export default function KeyGen({ loaderData }: Route.ComponentProps) {
	return (
		<div style={{ padding: "20px", fontFamily: "monospace" }}>
			<h1>Token Generator</h1>
			<p>Generate encrypted access tokens for your application</p>

			{loaderData && (
				<section style={{ marginBottom: "30px", padding: "15px", backgroundColor: "#e8f5e9", borderLeft: "4px solid #4caf50" }}>
					<h2>✅ Generated Token</h2>
					<p><strong>Plain Text:</strong> <code>{loaderData.plainText}</code></p>
					<p><strong>Encrypted:</strong> <code style={{ wordBreak: "break-all" }}>{loaderData.encrypted}</code></p>
					<p><strong>URL:</strong> <code><a href={loaderData.url} aria-label={`Navigate to application with generated token: ${loaderData.url}`}>{loaderData.url}</a></code></p>
				</section>
			)}

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
