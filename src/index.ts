/**
 * Cloudflare Workers Builds → Email Notifications via AWS SES
 *
 * This worker consumes build events from a Cloudflare Queue and sends
 * email notifications via AWS SES with:
 * - Live URLs for successful builds
 * - Error messages for failed builds
 * - Cancellation notices for cancelled builds
 *
 * @see https://developers.cloudflare.com/workers/ci-cd/builds
 * @see https://developers.cloudflare.com/queues/
 */
import type { Env, CloudflareEvent } from "./types";
import { getBuildStatus } from "./helpers";
import { fetchBuildUrls, fetchBuildLogs } from "./api";

async function sendEmailViaSES(
	env: Env,
	subject: string,
	body: string
): Promise<void> {
	const region = "eu-west-2";
	const url = `https://email.${region}.amazonaws.com/v2/email/outbound-emails`;

	const email = {
		FromEmailAddress: "cloudflare-build-notifications@sankala.com",
		Destination: {
			ToAddresses: ["hsankala@gmail.com"],
		},
		Content: {
			Simple: {
				Subject: { Data: subject },
				Body: { Text: { Data: body } },
			},
		},
	};

	// AWS SES API v2 — Signature Version 4
	const now = new Date();
	const amzdate = now.toISOString().replace(/[:-]|\.\d{3}/g, "").slice(0, 15) + "Z";
	const datestamp = amzdate.slice(0, 8);

	const bodyStr = JSON.stringify(email);
	const bodyHash = await sha256(bodyStr);

	const canonicalHeaders =
		`content-type:application/json\n` +
		`host:email.${region}.amazonaws.com\n` +
		`x-amz-date:${amzdate}\n`;

	const signedHeaders = "content-type;host;x-amz-date";

	const canonicalRequest = [
		"POST",
		"/v2/email/outbound-emails",
		"",
		canonicalHeaders,
		signedHeaders,
		bodyHash,
	].join("\n");

	const credentialScope = `${datestamp}/${region}/ses/aws4_request`;
	const stringToSign = [
		"AWS4-HMAC-SHA256",
		amzdate,
		credentialScope,
		await sha256(canonicalRequest),
	].join("\n");

	const signingKey = await getSigningKey(env.AWS_SECRET_ACCESS_KEY, datestamp, region);
	const signature = await hmacHex(signingKey, stringToSign);

	const authHeader =
		`AWS4-HMAC-SHA256 Credential=${env.AWS_ACCESS_KEY_ID}/${credentialScope}, ` +
		`SignedHeaders=${signedHeaders}, Signature=${signature}`;

	const response = await fetch(url, {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			"X-Amz-Date": amzdate,
			Authorization: authHeader,
		},
		body: bodyStr,
	});

	if (!response.ok) {
		const text = await response.text();
		throw new Error(`SES error ${response.status}: ${text}`);
	}
}

async function sha256(message: string): Promise<string> {
	const msgBuffer = new TextEncoder().encode(message);
	const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
	return Array.from(new Uint8Array(hashBuffer))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

async function hmac(key: ArrayBuffer, message: string): Promise<ArrayBuffer> {
	const cryptoKey = await crypto.subtle.importKey(
		"raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
	);
	return crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(message));
}

async function hmacHex(key: ArrayBuffer, message: string): Promise<string> {
	const buf = await hmac(key, message);
	return Array.from(new Uint8Array(buf))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

async function getSigningKey(secret: string, date: string, region: string): Promise<ArrayBuffer> {
	const kDate = await hmac(new TextEncoder().encode("AWS4" + secret), date);
	const kRegion = await hmac(kDate, region);
	const kService = await hmac(kRegion, "ses");
	return hmac(kService, "aws4_request");
}

export default {
	async queue(batch: MessageBatch<CloudflareEvent>, env: Env): Promise<void> {
		if (!env.AWS_ACCESS_KEY_ID || !env.AWS_SECRET_ACCESS_KEY) {
			console.error("AWS SES credentials are not configured");
			for (const message of batch.messages) {
				message.ack();
			}
			return;
		}

		for (const message of batch.messages) {
			try {
				const event = message.body;

				if (!event?.type || !event?.payload || !event?.metadata) {
					console.error("Invalid event structure:", JSON.stringify(event));
					message.ack();
					continue;
				}

				if (event.type.includes("started") || event.type.includes("queued")) {
					message.ack();
					continue;
				}

				const status = getBuildStatus(event);
				const meta = event.payload.buildTriggerMetadata;
				const worker = event.source.workerName ?? "unknown";
				const branch = meta?.branch ?? "unknown";
				const commit = meta?.commitMessage ?? "unknown";
				const author = meta?.author ?? "unknown";

				let subject: string;
				let body: string;

				if (status.isSucceeded) {
					const { previewUrl, liveUrl } = await fetchBuildUrls(event, env);
					subject = `✅ Build succeeded — ${worker} (${branch})`;
					body = [
						`Worker: ${worker}`,
						`Branch: ${branch}`,
						`Commit: ${commit}`,
						`Author: ${author}`,
						liveUrl ? `Live URL: ${liveUrl}` : null,
						previewUrl ? `Preview URL: ${previewUrl}` : null,
					].filter(Boolean).join("\n");
				} else if (status.isCancelled) {
					subject = `⚠️ Build cancelled — ${worker} (${branch})`;
					body = [
						`Worker: ${worker}`,
						`Branch: ${branch}`,
						`Commit: ${commit}`,
						`Author: ${author}`,
					].join("\n");
				} else {
					const logs = await fetchBuildLogs(event, env);
					subject = `❌ Build failed — ${worker} (${branch})`;
					body = [
						`Worker: ${worker}`,
						`Branch: ${branch}`,
						`Commit: ${commit}`,
						`Author: ${author}`,
						``,
						`Build log:`,
						...logs,
					].join("\n");
				}

				await sendEmailViaSES(env, subject, body);
				message.ack();
			} catch (error) {
				console.error("Error processing message:", error);
				message.ack();
			}
		}
	},
} satisfies ExportedHandler<Env, CloudflareEvent>;
