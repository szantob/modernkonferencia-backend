import type { Route } from "./+types/home";
import { Welcome } from "../welcome/welcome";
import crypto from "crypto";

const RATE_LIMIT_WINDOW = 15 * 60 * 1000; // 15 minutes
const MAX_ATTEMPTS = 5;

// In-memory store for rate limiting (replace with Redis in production)
const attemptMap = new Map<string, { count: number; resetTime: number }>();

// RSA Public Key (from your RSA key pair)
const PUBLIC_KEY = process.env.RSA_PUBLIC_KEY || `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCSZdW0UjnXLENtH/6/nXiWuDtm
GK/dGIp9d06cEHK8LsUBvKUqYvUlD5kMQEYZitu+K5Hl3rBj24gUbEYcoNOaMEd3
PLW5sH0kEjZGMWAF5vKSXzW2qzAKvRujW3nGcTvvBgES+VDnlMHbTMQWvN6J8D4X
LGfwQaLWeEbngeq3pQIDAQAB
-----END PUBLIC KEY-----`;

function decryptRSA(encryptedToken: string): string | null {
	try {
		// Decode base64 encrypted token
		const encryptedBuffer = Buffer.from(encryptedToken, "base64");
		
		// Decrypt using RSA public key
		const decrypted = crypto.publicDecrypt(
			{
				key: PUBLIC_KEY,
				padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
			},
			encryptedBuffer
		);
		
		return decrypted.toString("utf-8");
	} catch (error) {
		return null;
	}
}

function validateToken(decryptedToken: string): boolean {
	// Format should be: "entrypass" + 8-digit number (e.g., "entrypass00000001")
	const tokenRegex = /^entrypass\d{8}$/;
	return tokenRegex.test(decryptedToken);
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

export function loader({ context, request }: Route.LoaderArgs) {
	const clientIP = getClientIP(request);
	const url = new URL(request.url);
	const encryptedToken = url.searchParams.get("token");

	// Check rate limiting
	if (isRateLimited(clientIP)) {
		logUnauthorizedAccess(clientIP, encryptedToken, "Rate limit exceeded");
		throw new Response("Too many attempts. Please try again later.", {
			status: 429,
			statusText: "Too Many Requests",
		});
	}

	// Check if token is provided
	if (!encryptedToken) {
		logUnauthorizedAccess(clientIP, null, "No token provided");
		throw new Response("Access Denied", {
			status: 403,
			statusText: "Forbidden",
		});
	}

	// Decrypt the token
	const decryptedToken = decryptRSA(encryptedToken);

	if (!decryptedToken) {
		logUnauthorizedAccess(clientIP, encryptedToken, "Failed to decrypt token");
		throw new Response("Access Denied", {
			status: 403,
			statusText: "Forbidden",
		});
	}

	// Validate the decrypted token format
	if (!validateToken(decryptedToken)) {
		logUnauthorizedAccess(clientIP, encryptedToken, "Invalid token format");
		throw new Response("Access Denied", {
			status: 403,
			statusText: "Forbidden",
		});
	}

	return { message: context.cloudflare.env.VALUE_FROM_CLOUDFLARE };
}

export default function Home({ loaderData }: Route.ComponentProps) {
	return <Welcome message={loaderData.message} />;
}
