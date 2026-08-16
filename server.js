import "dotenv/config";
import http2 from "node:http2";
import crypto from "node:crypto";
import express from "express";
import { createClient } from "@supabase/supabase-js";
import { importPKCS8, SignJWT } from "jose";

const required = [
  "SUPABASE_URL",
  "SUPABASE_SERVICE_ROLE_KEY",
  "APPLE_TEAM_ID",
  "APPLE_KEY_ID",
  "APPLE_PRIVATE_KEY",
  "APPLE_BUNDLE_ID",
  "APPLE_APNS_ENVIRONMENT",
  "WEBHOOK_SECRET",
];

for (const name of required) {
  if (!process.env[name]) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
}

const PORT = Number(process.env.PORT || 3000);
const TURN_TOKEN_TTL_SECONDS = 3600;
const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID || "";
const TWILIO_AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN || "";
const TURN_CONFIGURED = Boolean(
  TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN
);
const APNS_ENVIRONMENT = process.env.APPLE_APNS_ENVIRONMENT;
const APNS_HOST =
  APNS_ENVIRONMENT === "production"
    ? "https://api.push.apple.com"
    : "https://api.sandbox.push.apple.com";

const APNS_TOPIC =
  process.env.APPLE_VOIP_TOPIC ||
  `${process.env.APPLE_BUNDLE_ID}.voip`;

const PRIVATE_KEY = process.env.APPLE_PRIVATE_KEY.replace(/\\n/g, "\n");

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  },
);

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "64kb" }));

let signingKeyPromise;
let cachedProviderToken = null;
let providerTokenCreatedAt = 0;

function getSigningKey() {
  signingKeyPromise ??= importPKCS8(PRIVATE_KEY, "ES256");
  return signingKeyPromise;
}

async function getProviderToken() {
  const nowSeconds = Math.floor(Date.now() / 1000);

  // Apple provider tokens are valid for up to one hour.
  // Refresh after 50 minutes.
  if (
    cachedProviderToken &&
    nowSeconds - providerTokenCreatedAt < 50 * 60
  ) {
    return cachedProviderToken;
  }

  const signingKey = await getSigningKey();

  cachedProviderToken = await new SignJWT({})
    .setProtectedHeader({
      alg: "ES256",
      kid: process.env.APPLE_KEY_ID,
    })
    .setIssuer(process.env.APPLE_TEAM_ID)
    .setIssuedAt(nowSeconds)
    .sign(signingKey);

  providerTokenCreatedAt = nowSeconds;
  return cachedProviderToken;
}

function safeEqual(received, expected) {
  const a = Buffer.from(received || "");
  const b = Buffer.from(expected || "");

  return (
    a.length === b.length &&
    crypto.timingSafeEqual(a, b)
  );
}

function sendApnsRequest(deviceToken, payload, providerToken) {
  return new Promise((resolve, reject) => {
    const client = http2.connect(APNS_HOST);

    const finishWithError = (error) => {
      client.close();
      reject(error);
    };

    client.once("error", finishWithError);

    const request = client.request({
      ":method": "POST",
      ":path": `/3/device/${deviceToken}`,
      authorization: `bearer ${providerToken}`,
      "apns-topic": APNS_TOPIC,
      "apns-push-type": "voip",
      "apns-priority": "10",
      "apns-expiration": "0",
      "content-type": "application/json",
    });

    let responseBody = "";
    let statusCode = 0;
    let apnsId = null;

    request.setEncoding("utf8");

    request.on("response", (headers) => {
      statusCode = Number(headers[":status"] || 0);
      apnsId = headers["apns-id"] || null;
    });

    request.on("data", (chunk) => {
      responseBody += chunk;
    });

    request.on("error", finishWithError);

    request.on("end", () => {
      client.close();

      let parsedBody = null;
      if (responseBody) {
        try {
          parsedBody = JSON.parse(responseBody);
        } catch {
          parsedBody = { raw: responseBody };
        }
      }

      resolve({
        ok: statusCode === 200,
        statusCode,
        apnsId,
        body: parsedBody,
      });
    });

    request.end(JSON.stringify(payload));
  });
}

async function requireAuthenticatedUser(request, response) {
  const authorization = request.get("authorization") || "";
  const match = authorization.match(/^Bearer\s+(.+)$/i);

  if (!match) {
    response.status(401).json({
      error: "Missing bearer token",
    });
    return null;
  }

  const accessToken = match[1];

  const { data, error } = await supabase.auth.getUser(accessToken);

  if (error || !data?.user) {
    response.status(401).json({
      error: "Invalid or expired session",
    });
    return null;
  }

  return data.user;
}

async function createTwilioNetworkTraversalToken() {
  if (!TURN_CONFIGURED) {
    throw new Error("TURN_NOT_CONFIGURED");
  }

  const url =
    `https://api.twilio.com/2010-04-01/Accounts/` +
    `${encodeURIComponent(TWILIO_ACCOUNT_SID)}/Tokens.json`;

  const basicAuth = Buffer.from(
    `${TWILIO_ACCOUNT_SID}:${TWILIO_AUTH_TOKEN}`
  ).toString("base64");

  const body = new URLSearchParams({
    Ttl: String(TURN_TOKEN_TTL_SECONDS),
  });

  const twilioResponse = await fetch(url, {
    method: "POST",
    headers: {
      authorization: `Basic ${basicAuth}`,
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json",
    },
    body,
  });

  const payload = await twilioResponse.json().catch(() => null);

  if (!twilioResponse.ok) {
    const message =
      payload?.message ||
      payload?.detail ||
      `Twilio NTS request failed (${twilioResponse.status})`;

    throw new Error(message);
  }

  const iceServers = Array.isArray(payload?.ice_servers)
    ? payload.ice_servers
        .filter((server) => server && server.urls)
        .map((server) => ({
          urls: server.urls,
          ...(server.username
            ? { username: server.username }
            : {}),
          ...(server.credential
            ? { credential: server.credential }
            : {}),
        }))
    : [];

  if (iceServers.length === 0) {
    throw new Error("Twilio returned no ICE servers");
  }

  return {
    iceServers,
    ttl: Number(payload?.ttl || TURN_TOKEN_TTL_SECONDS),
  };
}

async function deactivateToken(token, reason) {
  const { error } = await supabase
    .from("voip_push_tokens")
    .update({
      is_active: false,
      invalidated_at: new Date().toISOString(),
      last_error: reason,
      updated_at: new Date().toISOString(),
    })
    .eq("token", token);

  if (error) {
    console.warn("Could not deactivate VoIP token:", error.message);
  }
}

async function loadCallData(callRecord) {
  const { data: caller, error: callerError } = await supabase
    .from("profiles")
    .select("display_name, qall_id")
    .eq("id", callRecord.caller_id)
    .maybeSingle();

  if (callerError) {
    throw new Error(`Could not load caller: ${callerError.message}`);
  }

  const { data: tokens, error: tokenError } = await supabase
    .from("voip_push_tokens")
    .select("token, environment")
    .eq("user_id", callRecord.callee_id)
    .eq("platform", "ios")
    .eq("environment", APNS_ENVIRONMENT)
    .eq("is_active", true);

  if (tokenError) {
    throw new Error(`Could not load VoIP tokens: ${tokenError.message}`);
  }

  return {
    caller,
    tokens: tokens || [],
  };
}

app.get("/health", (_request, response) => {
  response.json({
    ok: true,
    service: "global-qall-voip-push",
    apnsEnvironment: APNS_ENVIRONMENT,
    turnConfigured: TURN_CONFIGURED,
  });
});

app.get("/api/turn-credentials", async (request, response) => {
  try {
    const user = await requireAuthenticatedUser(request, response);

    if (!user) {
      return;
    }

    if (!TURN_CONFIGURED) {
      return response.status(503).json({
        error: "TURN is not configured on this server",
      });
    }

    const token = await createTwilioNetworkTraversalToken();

    console.log("TURN credentials issued", {
      userId: user.id,
      iceServerCount: token.iceServers.length,
      ttl: token.ttl,
    });

    response.set("cache-control", "no-store");

    return response.json({
      iceServers: token.iceServers,
      ttl: token.ttl,
    });
  } catch (error) {
    console.error(
      "TURN credential request failed:",
      error instanceof Error ? error.message : error
    );

    return response.status(502).json({
      error: "Could not create TURN credentials",
    });
  }
});

app.post("/webhooks/calls", async (request, response) => {
  const suppliedSecret =
    request.get("x-global-qall-webhook-secret") || "";

  if (!safeEqual(suppliedSecret, process.env.WEBHOOK_SECRET)) {
    return response.status(401).json({
      error: "Unauthorized webhook",
    });
  }

  const payload = request.body;
  const call = payload?.record;

  if (
    payload?.type !== "INSERT" ||
    payload?.schema !== "public" ||
    payload?.table !== "calls"
  ) {
    return response.status(202).json({
      ignored: true,
      reason: "Unsupported webhook event",
    });
  }

  if (
    !call?.id ||
    !call?.caller_id ||
    !call?.callee_id ||
    call?.status !== "ringing"
  ) {
    return response.status(202).json({
      ignored: true,
      reason: "Not a valid ringing call",
    });
  }

  try {
    const { caller, tokens } = await loadCallData(call);

    if (tokens.length === 0) {
      return response.status(202).json({
        delivered: 0,
        reason: "No active VoIP token for callee",
      });
    }

    const callerName =
      caller?.display_name?.trim() ||
      caller?.qall_id ||
      "Global Qall caller";

    const handle = caller?.qall_id || "Global Qall";

    const apnsPayload = {
      aps: {
        "content-available": 1,
      },
      uuid: call.id,
      callId: call.id,
      callerId: call.caller_id,
      callerName,
      handle,
      callType: call.call_type === "video" ? "video" : "voice",
      hasVideo: call.call_type === "video",
      expiresAt: call.expires_at || null,
    };

    const providerToken = await getProviderToken();

    const results = await Promise.all(
      tokens.map(async ({ token }) => {
        try {
          const result = await sendApnsRequest(
            token,
            apnsPayload,
            providerToken,
          );

          const reason = result.body?.reason;

          if (
            result.statusCode === 410 ||
            reason === "BadDeviceToken" ||
            reason === "DeviceTokenNotForTopic" ||
            reason === "Unregistered"
          ) {
            await deactivateToken(
              token,
              reason || `APNs ${result.statusCode}`,
            );
          }

          return {
            tokenSuffix: token.slice(-8),
            ...result,
          };
        } catch (error) {
          return {
            tokenSuffix: token.slice(-8),
            ok: false,
            statusCode: 0,
            error:
              error instanceof Error
                ? error.message
                : String(error),
          };
        }
      }),
    );

    const delivered = results.filter((item) => item.ok).length;

    console.log("VoIP push result", {
      callId: call.id,
      delivered,
      attempted: results.length,
      results,
    });

    return response
      .status(delivered > 0 ? 200 : 502)
      .json({
        callId: call.id,
        delivered,
        attempted: results.length,
        results,
      });
  } catch (error) {
    console.error("VoIP webhook failed:", error);

    return response.status(500).json({
      error:
        error instanceof Error
          ? error.message
          : "VoIP push failed",
    });
  }
});

app.post('/webhooks/supabase/calls', express.json(), async (req, res) => {
  const secret = req.get('X-Webhook-Secret');

  if (secret !== process.env.WEBHOOK_SECRET) {
    return res.sendStatus(401);
  }

  console.log('Supabase webhook:', req.body);

  res.sendStatus(200);
});

app.use((error, _request, response, _next) => {
  console.error("Unhandled server error:", error);
  response.status(500).json({ error: "Internal server error" });
});

app.listen(PORT, () => {
  console.log(
    `Global Qall VoIP push server listening on port ${PORT}`,
  );
});
