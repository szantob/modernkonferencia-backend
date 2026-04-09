// Type augmentation for Cloudflare Worker secrets.
// These are set via `wrangler secret put` and are not declared in wrangler.json.
interface Env {
	RSA_PUBLIC_KEY: string;
	RSA_PRIVATE_KEY: string;
}
