const EXPO_PUSH_URL = "https://exp.host/--/api/v2/push/send";

function isExpoPushToken(value) {
  return (
    typeof value === "string" &&
    (value.startsWith("ExponentPushToken[") || value.startsWith("ExpoPushToken["))
  );
}

async function deactivateToken(supabase, table, column, token, reason) {
  const { error } = await supabase
    .from(table)
    .update({ is_active: false, updated_at: new Date().toISOString() })
    .eq(column, token);

  if (error) {
    console.warn("[ANDROID DIRECT CALL PUSH] Could not deactivate token", {
      table,
      tokenSuffix: token.slice(-12),
      reason,
      error: error.message,
    });
  }
}

let firebaseMessagingPromise = null;

async function getFirebaseMessaging() {
  if (!firebaseMessagingPromise) {
    firebaseMessagingPromise = (async () => {
      const { getApps, initializeApp, applicationDefault, cert } =
        await import("firebase-admin/app");
      const { getMessaging } = await import("firebase-admin/messaging");

      if (getApps().length === 0) {
        const rawServiceAccount = process.env.FIREBASE_SERVICE_ACCOUNT_JSON?.trim();

        if (rawServiceAccount) {
          initializeApp({ credential: cert(JSON.parse(rawServiceAccount)) });
        } else {
          initializeApp({ credential: applicationDefault() });
        }
      }

      return getMessaging();
    })();
  }

  return firebaseMessagingPromise;
}

async function sendNativeFcm({ supabase, tokens, data, ttlSeconds }) {
  if (!tokens.length) {
    return { attempted: 0, delivered: 0, failed: 0 };
  }

  const messaging = await getFirebaseMessaging();
  const response = await messaging.sendEachForMulticast({
    tokens,
    data,
    android: {
      priority: "high",
      ttl: ttlSeconds * 1000,
    },
  });

  for (let i = 0; i < response.responses.length; i += 1) {
    const result = response.responses[i];
    if (result.success) continue;

    const code = result.error?.code || "unknown";
    if (
      code === "messaging/registration-token-not-registered" ||
      code === "messaging/invalid-registration-token"
    ) {
      await deactivateToken(
        supabase,
        "android_fcm_tokens",
        "fcm_token",
        tokens[i],
        code,
      );
    }
  }

  return {
    attempted: tokens.length,
    delivered: response.successCount,
    failed: response.failureCount,
  };
}

async function sendExpoFallback({ supabase, tokens, data, callerName, isVideo, ttlSeconds }) {
  if (!tokens.length) {
    return { attempted: 0, delivered: 0, tickets: [] };
  }

  // This is intentionally a regular notification message, not the removed
  // Sprint 12.5B headless TaskManager payload. It preserves the known-working
  // 12.5A Android OS notification path as a fallback.
  const messages = tokens.map((token) => ({
    to: token,
    priority: "high",
    ttl: ttlSeconds,
    channelId: "calls",
    title: callerName,
    body: isVideo ? "Incoming video call" : "Incoming voice call",
    data,
  }));

  const response = await fetch(EXPO_PUSH_URL, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Accept-Encoding": "gzip, deflate",
      "Content-Type": "application/json",
    },
    body: JSON.stringify(messages),
  });

  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(
      `Expo push request failed (${response.status}): ${JSON.stringify(body)}`,
    );
  }

  const tickets = Array.isArray(body?.data)
    ? body.data
    : body?.data
      ? [body.data]
      : [];

  let delivered = 0;
  for (let i = 0; i < messages.length; i += 1) {
    const ticket = tickets[i];
    const token = messages[i].to;
    if (ticket?.status === "ok") {
      delivered += 1;
      continue;
    }

    if (ticket?.details?.error === "DeviceNotRegistered") {
      await deactivateToken(
        supabase,
        "message_push_tokens",
        "expo_push_token",
        token,
        "DeviceNotRegistered",
      );
    }
  }

  return { attempted: messages.length, delivered, tickets };
}

export async function sendAndroidDirectCallPush({ supabase, call }) {
  if (
    !call?.id ||
    !call?.caller_id ||
    !call?.callee_id ||
    call?.status !== "ringing"
  ) {
    return {
      attempted: 0,
      delivered: 0,
      ignored: true,
      reason: "Not a valid ringing call",
    };
  }

  const [
    { data: caller, error: callerError },
    { data: fcmRows, error: fcmError },
    { data: expoRows, error: expoError },
  ] = await Promise.all([
    supabase
      .from("profiles")
      .select("display_name, qall_id")
      .eq("id", call.caller_id)
      .maybeSingle(),
    supabase
      .from("android_fcm_tokens")
      .select("fcm_token")
      .eq("user_id", call.callee_id)
      .eq("is_active", true),
    supabase
      .from("message_push_tokens")
      .select("expo_push_token")
      .eq("user_id", call.callee_id)
      .eq("platform", "android")
      .eq("is_active", true),
  ]);

  if (callerError) {
    throw new Error(`Could not load Android caller profile: ${callerError.message}`);
  }
  if (fcmError) {
    throw new Error(`Could not load Android FCM tokens: ${fcmError.message}`);
  }
  if (expoError) {
    throw new Error(`Could not load Android Expo tokens: ${expoError.message}`);
  }

  const fcmTokens = (fcmRows || []).map((row) => row.fcm_token).filter(Boolean);
  const expoTokens = (expoRows || [])
    .map((row) => row.expo_push_token)
    .filter(isExpoPushToken);

  const callerName =
    caller?.display_name?.trim() || caller?.qall_id || "Global Qall caller";
  const qallId = caller?.qall_id || "Global Qall";
  const isVideo = call.call_type === "video";
  const ttlSeconds = Math.max(
    5,
    Math.min(
      60,
      call.expires_at
        ? Math.floor((new Date(call.expires_at).getTime() - Date.now()) / 1000)
        : 45,
    ),
  );

  const data = {
    type: "direct_call",
    callId: String(call.id),
    callerId: String(call.caller_id),
    callerName: String(callerName),
    qallId: String(qallId),
    callType: isVideo ? "video" : "voice",
    expiresAt: String(call.expires_at || ""),
  };

  let nativeResult = { attempted: 0, delivered: 0, failed: 0 };
  let nativeError = null;

  if (fcmTokens.length) {
    try {
      nativeResult = await sendNativeFcm({
        supabase,
        tokens: fcmTokens,
        data,
        ttlSeconds,
      });
    } catch (error) {
      nativeError = error instanceof Error ? error.message : String(error);
      console.warn("[ANDROID DIRECT CALL FCM] Native FCM failed; using Expo fallback", {
        callId: call.id,
        error: nativeError,
      });
    }
  }

  // Avoid duplicate ringing when native FCM was successfully accepted.
  // Use the old Expo notification-bearing path only when native FCM is not
  // available or failed completely.
  let expoResult = { attempted: 0, delivered: 0, tickets: [] };
  if (nativeResult.delivered === 0) {
    expoResult = await sendExpoFallback({
      supabase,
      tokens: expoTokens,
      data,
      callerName,
      isVideo,
      ttlSeconds,
    });
  }

  console.log("[ANDROID DIRECT CALL PUSH]", {
    callId: call.id,
    calleeId: call.callee_id,
    nativeFcm: nativeResult,
    nativeError,
    expoFallback: {
      attempted: expoResult.attempted,
      acceptedByExpo: expoResult.delivered,
    },
  });

  return {
    attempted: nativeResult.attempted + expoResult.attempted,
    delivered: nativeResult.delivered + expoResult.delivered,
    nativeFcm: nativeResult,
    expoFallback: expoResult,
  };
}
