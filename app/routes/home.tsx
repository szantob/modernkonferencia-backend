import type { Route } from "./+types/home";
import { Welcome } from "../welcome/welcome";

const VALID_TOKEN = process.env.CONTENT_TOKEN || "your-secret-token";
const RATE_LIMIT_WINDOW = 15 * 60 * 1000; // 15 minutes
const MAX_ATTEMPTS = 5;

// In-memory store for rate limiting (replace with Redis in production)
const attemptMap = new Map<string, { count: number; resetTime: number }>();

function timingSafeCompare(a: string, b: string): boolean {
	if (a.length !== b.length) {
		return false;
	}
	let result = 0;
	for (let i = 0; i < a.length; i++) {
		result |= a.charCodeAt(i) ^ b.charCodeAt(i);
	}
	return result === 0;
}

function logUnauthorizedAccess(ip: string, token: string | null): void {
	const timestamp = new Date().toISOString();
	console.warn(`[${timestamp}] Unauthorized access attempt from IP: ${ip}, token: ${token || "none"}`);
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
	const token = url.searchParams.get("token");

	// Check rate limiting
	if (isRateLimited(clientIP)) {
		logUnauthorizedAccess(clientIP, token);
		throw new Response("Too many attempts. Please try again later.", {
			status: 429,
			statusText: "Too Many Requests",
		});
	}

	// Validate token using timing-safe comparison
	const isAuthorized = token && timingSafeCompare(token, VALID_TOKEN);

	if (!isAuthorized) {
		logUnauthorizedAccess(clientIP, token);
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
