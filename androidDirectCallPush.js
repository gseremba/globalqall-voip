const EXPO_PUSH_URL =
  "https://exp.host/--/api/v2/push/send";

function isExpoPushToken(value) {
  return (
    typeof value === "string" &&
    (
      value.startsWith("ExponentPushToken[") ||
      value.startsWith("ExpoPushToken[")
    )
  );
}

async function deactivateMessagePushToken(
  supabase,
  expoPushToken,
  reason,
) {
  const { error } = await supabase
    .from("message_push_tokens")
    .update({
      is_active: false,
      updated_at: new Date().toISOString(),
    })
    .eq("expo_push_token", expoPushToken);

  if (error) {
    console.warn(
      "[ANDROID DIRECT CALL PUSH] Could not deactivate token",
      {
        tokenSuffix: expoPushToken.slice(-12),
        reason,
        error: error.message,
      },
    );
  }
}

export async function sendAndroidDirectCallPush({
  supabase,
  call,
}) {
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
    { data: tokenRows, error: tokenError },
  ] = await Promise.all([
    supabase
      .from("profiles")
      .select("display_name, qall_id")
      .eq("id", call.caller_id)
      .maybeSingle(),

    supabase
      .from("message_push_tokens")
      .select("expo_push_token")
      .eq("user_id", call.callee_id)
      .eq("platform", "android")
      .eq("is_active", true),
  ]);

  if (callerError) {
    throw new Error(
      `Could not load Android caller profile: ${callerError.message}`,
    );
  }

  if (tokenError) {
    throw new Error(
      `Could not load Android push tokens: ${tokenError.message}`,
    );
  }

  const tokens = (tokenRows || [])
    .map((row) => row.expo_push_token)
    .filter(isExpoPushToken);

  if (tokens.length === 0) {
    console.log("[ANDROID DIRECT CALL PUSH]", {
      callId: call.id,
      calleeId: call.callee_id,
      attempted: 0,
      delivered: 0,
      reason: "No active Android Expo push token",
    });

    return {
      attempted: 0,
      delivered: 0,
      reason: "No active Android Expo push token",
    };
  }

  const callerName =
    caller?.display_name?.trim() ||
    caller?.qall_id ||
    "Global Qall caller";

  const qallId =
    caller?.qall_id || "Global Qall";

  const isVideo = call.call_type === "video";
  const ttlSeconds = Math.max(
    5,
    Math.min(
      60,
      call.expires_at
        ? Math.floor(
            (
              new Date(call.expires_at).getTime() -
              Date.now()
            ) / 1000
          )
        : 45,
    ),
  );

  // Sprint 12.5B:
  // Data-only high-priority push. Do not include title/body/channelId here.
  // A data-only Android notification can start the Expo notification
  // background task even when the app is terminated. The task then hands the
  // call to Android ConnectionService / CallKeep. If native presentation is
  // unavailable, the app posts its own local notification fallback.
  const messages = tokens.map((token) => ({
    to: token,
    priority: "high",
    ttl: ttlSeconds,
    data: {
      type: "direct_call",
      callId: call.id,
      callerId: call.caller_id,
      callerName,
      qallId,
      callType: isVideo ? "video" : "voice",
      expiresAt: call.expires_at || null,
    },
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

  const body = await response
    .json()
    .catch(() => ({}));

  if (!response.ok) {
    throw new Error(
      `Expo push request failed (${response.status}): ${
        JSON.stringify(body)
      }`,
    );
  }

  const tickets = Array.isArray(body?.data)
    ? body.data
    : body?.data
      ? [body.data]
      : [];

  let delivered = 0;

  for (let index = 0; index < messages.length; index += 1) {
    const ticket = tickets[index];
    const token = messages[index].to;

    if (ticket?.status === "ok") {
      delivered += 1;
      continue;
    }

    const errorCode = ticket?.details?.error || null;

    if (errorCode === "DeviceNotRegistered") {
      await deactivateMessagePushToken(
        supabase,
        token,
        errorCode,
      );
    }
  }

  console.log("[ANDROID DIRECT CALL PUSH]", {
    callId: call.id,
    calleeId: call.callee_id,
    attempted: messages.length,
    acceptedByExpo: delivered,
    tickets,
  });

  return {
    attempted: messages.length,
    delivered,
    tickets,
  };
}
