import type { Route } from "./+types/home";

const RATE_LIMIT_WINDOW = 15 * 60 * 1000; // 15 minutes
const MAX_ATTEMPTS = 500;

// In-memory store for rate limiting (replace with Redis in production)
const attemptMap = new Map<string, { count: number; resetTime: number }>();

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

async function verifySignature(signatureBase64: string, plainText: string, publicKeyPem: string): Promise<boolean> {
	try {
		const signatureBytes = Uint8Array.from(atob(signatureBase64), (c) => c.charCodeAt(0));

		const publicKey = await crypto.subtle.importKey(
			"spki",
			pemToArrayBuffer(publicKeyPem),
			{ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
			false,
			["verify"]
		);

		const encodedData = new TextEncoder().encode(plainText);
		return await crypto.subtle.verify("RSASSA-PKCS1-v1_5", publicKey, signatureBytes, encodedData);
	} catch {
		return false;
	}
}

function validateToken(plainText: string): boolean {
	// Format should be: "entrypass" + 8-digit number (e.g., "entrypass00000001")
	const tokenRegex = /^entrypass\d{8}$/;
	return tokenRegex.test(plainText);
}

function logUnauthorizedAccess(ip: string, token: string | null, reason: string): void {
	const timestamp = new Date().toISOString();
	console.warn(
		`[${timestamp}] Unauthorized access attempt from IP: ${ip}, reason: ${reason}, token: ${token || "none"}`
	);
}

function isRateLimited(ip: string): boolean {
	const now = Date.now();
	const attempts = attemptMap.get(ip);

	if (!attempts) {
		attemptMap.set(ip, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
		return false;
	}

	if (now > attempts.resetTime) {
		attemptMap.set(ip, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
		return false;
	}

	attempts.count++;
	return attempts.count > MAX_ATTEMPTS;
}

function getClientIP(request: Request): string {
	return (
		request.headers.get("cf-connecting-ip") ||
		request.headers.get("x-forwarded-for")?.split(",")[0] ||
		request.headers.get("x-real-ip") ||
		"unknown"
	);
}

export function meta({}: Route.MetaArgs) {
	return [
		{ title: "New React Router App" },
		{ name: "description", content: "Welcome to React Router!" },
	];
}

export async function loader({ context, request }: Route.LoaderArgs) {
	const clientIP = getClientIP(request);
	const url = new URL(request.url);
	const signatureToken = url.searchParams.get("token");
	const tokenId = url.searchParams.get("id");

	// Check rate limiting
	if (isRateLimited(clientIP)) {
		logUnauthorizedAccess(clientIP, signatureToken, "Rate limit exceeded");
		throw new Response("Too many attempts. Please try again later.", {
			status: 429,
			statusText: "Too Many Requests",
		});
	}

	// Check if token and id are provided
	if (!signatureToken || !tokenId) {
		logUnauthorizedAccess(clientIP, null, "No token or id provided");
		throw new Response("Access Denied", {
			status: 403,
			statusText: "Forbidden",
		});
	}

	// Validate the plaintext token format first
	if (!validateToken(tokenId)) {
		logUnauthorizedAccess(clientIP, signatureToken, "Invalid token format");
		throw new Response("Access Denied", {
			status: 403,
			statusText: "Forbidden",
		});
	}

	// Verify the signature against the plaintext
	const publicKeyPem = context.cloudflare.env.RSA_PUBLIC_KEY;
	if (!publicKeyPem) {
		throw new Response("Server configuration error", { status: 500 });
	}
	const isValid = await verifySignature(signatureToken, tokenId, publicKeyPem);

	if (!isValid) {
		logUnauthorizedAccess(clientIP, signatureToken, "Invalid signature");
		throw new Response("Access Denied", {
			status: 403,
			statusText: "Forbidden",
		});
	}

	return {
		message: context.cloudflare.env.VALUE_FROM_CLOUDFLARE,
		videoId: context.cloudflare.env.CLOUDFLARE_STREAM_VIDEO_ID,
	};
}

export default function Home({ loaderData }: Route.ComponentProps) {
	return (
		<div style={{ display: "flex", justifyContent: "center", alignItems: "center", minHeight: "100vh", backgroundColor: "#000" }}>
			<iframe
				src={`https://iframe.cloudflarestream.com/${loaderData.videoId}`}
				style={{ border: "none", width: "100%", maxWidth: "960px", aspectRatio: "16/9" }}
				allow="accelerometer; gyroscope; autoplay; encrypted-media; picture-in-picture;"
				allowFullScreen
				title="Conference Video"
			/>
		</div>
	);
}
