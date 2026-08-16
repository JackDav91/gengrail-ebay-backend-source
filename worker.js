/*
  Gengrail TCG — eBay Production OAuth backend
  Cloudflare Worker + Workers KV

  Secrets:
    EBAY_CLIENT_SECRET  -> Cloudflare secret (NEVER commit)

  Variables:
    EBAY_CLIENT_ID      -> Sandbox App ID / Client ID
    EBAY_RUNAME         -> Sandbox OAuth-enabled RuName
    APP_URL             -> https://jackdav91.github.io/gengrail-business-log/
    APP_ORIGIN          -> https://jackdav91.github.io

  KV binding:
    EBAY_AUTH
*/

const EBAY_AUTH_URL = "https://auth.ebay.com/oauth2/authorize";
const EBAY_API = "https://api.ebay.com";
const EBAY_MEDIA_API = "https://apim.ebay.com/commerce/media/v1_beta";
const TOKEN_URL = EBAY_API + "/identity/v1/oauth2/token";

const SCOPES = [
  "https://api.ebay.com/oauth/api_scope/sell.account",
  "https://api.ebay.com/oauth/api_scope/sell.inventory",
  "https://api.ebay.com/oauth/api_scope/sell.fulfillment"
];

const TOKEN_KEY = "production:ebay_tokens";

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...extra
    }
  });
}

function corsHeaders(env) {
  return {
    "access-control-allow-origin": env.APP_ORIGIN,
    "access-control-allow-methods": "GET,POST,OPTIONS",
    "access-control-allow-headers": "content-type,x-filename",
    "access-control-max-age": "86400",
    "vary": "Origin"
  };
}

function withCors(response, env) {
  const headers = new Headers(response.headers);
  const cors = corsHeaders(env);
  Object.entries(cors).forEach(([k, v]) => headers.set(k, v));
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

function requireConfig(env) {
  const missing = [];
  for (const key of ["EBAY_CLIENT_ID", "EBAY_CLIENT_SECRET", "EBAY_RUNAME", "APP_URL", "APP_ORIGIN"]) {
    if (!env[key]) missing.push(key);
  }
  if (!env.EBAY_AUTH) missing.push("EBAY_AUTH (KV binding)");
  return missing;
}

function randomState() {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
}

async function readTokens(env) {
  const raw = await env.EBAY_AUTH.get(TOKEN_KEY);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { return null; }
}

async function writeTokens(env, tokenResponse) {
  const now = Date.now();
  const existing = await readTokens(env);
  const record = {
    access_token: tokenResponse.access_token || existing?.access_token || "",
    access_expires_at: tokenResponse.expires_in
      ? now + (Number(tokenResponse.expires_in) * 1000)
      : existing?.access_expires_at || 0,
    refresh_token: tokenResponse.refresh_token || existing?.refresh_token || "",
    refresh_expires_at: tokenResponse.refresh_token_expires_in
      ? now + (Number(tokenResponse.refresh_token_expires_in) * 1000)
      : existing?.refresh_expires_at || 0,
    scope: tokenResponse.scope || existing?.scope || SCOPES.join(" "),
    token_type: tokenResponse.token_type || existing?.token_type || "User Access Token",
    updated_at: new Date(now).toISOString()
  };
  await env.EBAY_AUTH.put(TOKEN_KEY, JSON.stringify(record));
  return record;
}

function basicAuth(env) {
  return "Basic " + btoa(env.EBAY_CLIENT_ID + ":" + env.EBAY_CLIENT_SECRET);
}

async function exchangeCode(env, code) {
  const body = new URLSearchParams();
  body.set("grant_type", "authorization_code");
  body.set("code", code);
  body.set("redirect_uri", env.EBAY_RUNAME);

  const res = await fetch(TOKEN_URL, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      "authorization": basicAuth(env)
    },
    body
  });

  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { raw: text }; }
  if (!res.ok) {
    throw new Error("eBay token exchange failed (" + res.status + "): " + JSON.stringify(data));
  }
  return data;
}

async function refreshAccessToken(env, refreshToken) {
  const body = new URLSearchParams();
  body.set("grant_type", "refresh_token");
  body.set("refresh_token", refreshToken);
  body.set("scope", SCOPES.join(" "));

  const res = await fetch(TOKEN_URL, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      "authorization": basicAuth(env)
    },
    body
  });

  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { raw: text }; }
  if (!res.ok) {
    throw new Error("eBay token refresh failed (" + res.status + "): " + JSON.stringify(data));
  }
  return data;
}

async function getAccessToken(env) {
  let tokens = await readTokens(env);
  if (!tokens?.refresh_token) throw new Error("eBay is not connected yet.");

  // Keep a 2-minute safety margin.
  if (tokens.access_token && Number(tokens.access_expires_at || 0) > Date.now() + 120000) {
    return tokens.access_token;
  }

  const refreshed = await refreshAccessToken(env, tokens.refresh_token);
  tokens = await writeTokens(env, refreshed);
  return tokens.access_token;
}

async function getAppAccessToken(env) {
  const cacheKey = "production:ebay_app_token";
  try {
    const cached = await env.EBAY_AUTH.get(cacheKey);
    if (cached) {
      const parsed = JSON.parse(cached);
      if (parsed?.access_token && Number(parsed.expires_at || 0) > Date.now() + 12e4) return parsed.access_token;
    }
  } catch {}
  const body = new URLSearchParams();
  body.set("grant_type", "client_credentials");
  body.set("scope", "https://api.ebay.com/oauth/api_scope");
  const res = await fetch(TOKEN_URL, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      "authorization": basicAuth(env)
    },
    body
  });
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { raw: text }; }
  if (!res.ok) throw new Error("eBay app token failed (" + res.status + "): " + JSON.stringify(data));
  const record = {
    access_token: data.access_token,
    expires_at: Date.now() + Number(data.expires_in || 7200) * 1000
  };
  await env.EBAY_AUTH.put(cacheKey, JSON.stringify(record), { expirationTtl: Math.max(60, Number(data.expires_in || 7200) - 60) });
  return record.access_token;
}

async function taxonomyFetch(env, path) {
  const token = await getAppAccessToken(env);
  const res = await fetch(EBAY_API + path, {
    method: "GET",
    headers: { "authorization": "Bearer " + token, "accept": "application/json" }
  });
  const text = await res.text();
  let data = null;
  if (text) { try { data = JSON.parse(text); } catch { data = { raw: text }; } }
  if (!res.ok) throw new Error("eBay Taxonomy API failed (" + res.status + "): " + JSON.stringify(data));
  return data;
}

async function ebayFetch(env, path, options = {}) {
  const accessToken = await getAccessToken(env);
  const headers = new Headers(options.headers || {});
  headers.set("authorization", "Bearer " + accessToken);
  headers.set("accept", "application/json");

  // eBay Inventory API requires a valid Content-Language when listing
  // user-defined text. Gengrail is currently publishing to EBAY_GB.
  if (!headers.has("content-language")) headers.set("content-language", "en-GB");
  if (!headers.has("accept-language")) headers.set("accept-language", "en-GB");
  if (!headers.has("x-ebay-c-marketplace-id")) headers.set("x-ebay-c-marketplace-id", "EBAY_GB");

  if (options.body && !headers.has("content-type")) {
    headers.set("content-type", "application/json");
  }

  const res = await fetch(EBAY_API + path, {
    ...options,
    headers
  });

  const text = await res.text();
  let data = null;
  if (text) {
    try { data = JSON.parse(text); } catch { data = { raw: text }; }
  }
  return { ok: res.ok, status: res.status, data, headers: res.headers };
}

async function handleStart(request, env) {
  const state = randomState();
  await env.EBAY_AUTH.put("production:state:" + state, "1", { expirationTtl: 600 });

  const url = new URL(EBAY_AUTH_URL);
  url.searchParams.set("client_id", env.EBAY_CLIENT_ID);
  url.searchParams.set("redirect_uri", env.EBAY_RUNAME);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", SCOPES.join(" "));
  url.searchParams.set("state", state);

  return Response.redirect(url.toString(), 302);
}

async function handleCallback(request, env) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const error = url.searchParams.get("error");
  const errorDescription = url.searchParams.get("error_description");

  if (error) {
    const declined = new URL("ebay-declined.html", env.APP_URL);
    declined.searchParams.set("reason", errorDescription || error);
    return Response.redirect(declined.toString(), 302);
  }

  if (!code || !state) {
    return json({
      ok: false,
      error: "missing_oauth_parameters",
      message: "eBay did not return both code and state."
    }, 400);
  }

  const savedState = await env.EBAY_AUTH.get("production:state:" + state);
  if (!savedState) {
    return json({
      ok: false,
      error: "invalid_state",
      message: "OAuth state is missing, invalid or expired."
    }, 400);
  }
  await env.EBAY_AUTH.delete("production:state:" + state);

  try {
    const tokenResponse = await exchangeCode(env, code);
    await writeTokens(env, tokenResponse);

    const success = new URL(env.APP_URL);
    success.searchParams.set("ebay", "connected");
    return Response.redirect(success.toString(), 302);
  } catch (err) {
    return json({
      ok: false,
      error: "token_exchange_failed",
      message: String(err?.message || err)
    }, 502);
  }
}

async function handleStatus(env) {
  const tokens = await readTokens(env);
  if (!tokens?.refresh_token) {
    return json({
      ok: true,
      environment: "production",
      connected: false
    });
  }

  return json({
    ok: true,
    environment: "production",
    connected: true,
    accessTokenUsable: Number(tokens.access_expires_at || 0) > Date.now() + 120000,
    accessExpiresAt: tokens.access_expires_at ? new Date(tokens.access_expires_at).toISOString() : null,
    refreshExpiresAt: tokens.refresh_expires_at ? new Date(tokens.refresh_expires_at).toISOString() : null,
    updatedAt: tokens.updated_at || null,
    scopes: SCOPES
  });
}

async function handleDisconnect(env) {
  await env.EBAY_AUTH.delete(TOKEN_KEY);
  return json({ ok: true, connected: false });
}

async function handlePolicies(env) {
  const marketplace = "EBAY_GB";
  const [payment, fulfillment, returns] = await Promise.all([
    ebayFetch(env, "/sell/account/v1/payment_policy?marketplace_id=" + marketplace),
    ebayFetch(env, "/sell/account/v1/fulfillment_policy?marketplace_id=" + marketplace),
    ebayFetch(env, "/sell/account/v1/return_policy?marketplace_id=" + marketplace)
  ]);

  return json({
    ok: payment.ok && fulfillment.ok && returns.ok,
    marketplace,
    payment: { status: payment.status, data: payment.data },
    fulfillment: { status: fulfillment.status, data: fulfillment.data },
    returns: { status: returns.status, data: returns.data }
  }, payment.ok && fulfillment.ok && returns.ok ? 200 : 502);
}

async function handleInventoryLocations(env) {
  const ebay = await ebayFetch(env, "/sell/inventory/v1/location?limit=100");
  return json({ ok: ebay.ok, status: ebay.status, data: ebay.data },
    ebay.ok ? 200 : ebay.status || 502);
}

async function handleCreateInventoryLocation(request, env) {
  let body;
  try { body = await request.json(); }
  catch {
    return json({ ok:false, error:"invalid_json", message:"Request body must be valid JSON." }, 400);
  }

  const merchantLocationKey = String(body?.merchantLocationKey || "").trim();
  if (!merchantLocationKey) {
    return json({ ok:false, error:"merchant_location_key_required", message:"merchantLocationKey is required." }, 400);
  }
  if (!body?.location || typeof body.location !== "object") {
    return json({ ok:false, error:"location_required", message:"location is required." }, 400);
  }

  const payload = {
    location: body.location,
    locationTypes: Array.isArray(body.locationTypes) && body.locationTypes.length ? body.locationTypes : ["WAREHOUSE"],
    name: String(body?.name || "Gengrail TCG"),
    merchantLocationStatus: body?.merchantLocationStatus || "ENABLED"
  };
  if (body?.phone) payload.phone = String(body.phone);
  if (body?.specialHours) payload.specialHours = body.specialHours;
  if (body?.operatingHours) payload.operatingHours = body.operatingHours;

  const ebay = await ebayFetch(env,
    "/sell/inventory/v1/location/" + encodeURIComponent(merchantLocationKey),
    { method:"POST", body:JSON.stringify(payload) });

  return json({ ok:ebay.ok, status:ebay.status, merchantLocationKey, data:ebay.data },
    ebay.ok ? 200 : ebay.status || 502);
}


function normaliseText(value = "") {
  return String(value || "").trim().toLowerCase();
}

function descriptorValueName(value) {
  // Current Metadata API documentation uses conditionDescriptorValueName.
  // Keep the older alias too so the resolver is tolerant of response variations.
  return String(
    value?.conditionDescriptorValueName ??
    value?.conditionDescriptorValue ??
    ""
  );
}

function conditionTarget(conditionApi = "USED_VERY_GOOD") {
  const api = String(conditionApi || "USED_VERY_GOOD").toUpperCase();

  if (api === "LIKE_NEW") {
    return {
      api,
      conditionId: "2750",
      graded: true
    };
  }

  if (api === "NEW") {
    return {
      api,
      conditionId: "1000",
      graded: false
    };
  }

  // eBay uses USED_VERY_GOOD / condition ID 4000 as the umbrella
  // Inventory API condition for ungraded trading cards. The actual card
  // condition is then supplied through the Card Condition descriptor.
  return {
    api: "USED_VERY_GOOD",
    conditionId: "4000",
    graded: false
  };
}

function resolveConditionMetadata(conditionPolicy, conditionApi) {
  const target = conditionTarget(conditionApi);
  const itemConditions = Array.isArray(conditionPolicy?.itemConditions)
    ? conditionPolicy.itemConditions
    : [];

  const itemCondition =
    itemConditions.find(c => String(c?.conditionId || "") === target.conditionId) ||
    null;

  if (!itemCondition) {
    return {
      conditionApi: target.api,
      conditionId: target.conditionId,
      itemConditionFound: false,
      descriptorRequired: target.api !== "NEW",
      descriptorNameId: "",
      descriptorName: "",
      descriptorValueId: "",
      descriptorValue: "",
      graded: target.graded,
      message: "eBay did not return the expected item condition for this category."
    };
  }

  const descriptors = Array.isArray(itemCondition?.conditionDescriptors)
    ? itemCondition.conditionDescriptors
    : [];

  if (target.api === "NEW") {
    return {
      conditionApi: target.api,
      conditionId: String(itemCondition.conditionId || target.conditionId),
      itemConditionFound: true,
      descriptorRequired: false,
      descriptorNameId: "",
      descriptorName: "",
      descriptorValueId: "",
      descriptorValue: "",
      graded: false,
      message: "New condition resolved; no trading-card condition descriptor is required."
    };
  }

  if (target.graded) {
    return {
      conditionApi: target.api,
      conditionId: String(itemCondition.conditionId || target.conditionId),
      itemConditionFound: true,
      descriptorRequired: true,
      descriptorNameId: "",
      descriptorName: "",
      descriptorValueId: "",
      descriptorValue: "",
      graded: true,
      requiredDescriptors: descriptors.map(d => ({
        id: String(d?.conditionDescriptorId || ""),
        name: String(d?.conditionDescriptorName || ""),
        usage: String(d?.conditionDescriptorConstraint?.usage || ""),
        values: (Array.isArray(d?.conditionDescriptorValues) ? d.conditionDescriptorValues : []).map(v => ({
          id: String(v?.conditionDescriptorValueId || ""),
          value: descriptorValueName(v)
        }))
      })),
      message: "Graded card detected. Grader and Grade must be supplied before publishing."
    };
  }

  // Ungraded trading cards require the Card Condition descriptor (ID 40001).
  const descriptor =
    descriptors.find(d => String(d?.conditionDescriptorId || "") === "40001") ||
    descriptors.find(d => normaliseText(d?.conditionDescriptorName) === "card condition") ||
    descriptors.find(d => normaliseText(d?.conditionDescriptorHelpText).includes("ungraded")) ||
    null;

  if (!descriptor) {
    return {
      conditionApi: target.api,
      conditionId: String(itemCondition.conditionId || target.conditionId),
      itemConditionFound: true,
      descriptorRequired: true,
      descriptorNameId: "",
      descriptorName: "",
      descriptorValueId: "",
      descriptorValue: "",
      graded: false,
      message: "Card Condition descriptor was not returned for this category."
    };
  }

  const values = Array.isArray(descriptor?.conditionDescriptorValues)
    ? descriptor.conditionDescriptorValues
    : [];

  // Do not confuse the umbrella API enum USED_VERY_GOOD with a literal
  // "Very Good" descriptor. For CCG Individual Cards (183454), eBay's
  // permitted ungraded values are category-specific. Prefer eBay's own
  // defaultConditionDescriptorValueId; if absent, prefer Near Mint or Better,
  // then the first permitted value.
  const defaultValueId = String(
    descriptor?.conditionDescriptorConstraint?.defaultConditionDescriptorValueId || ""
  );

  const resolvedValue =
    (defaultValueId
      ? values.find(v => String(v?.conditionDescriptorValueId || "") === defaultValueId)
      : null) ||
    values.find(v => normaliseText(descriptorValueName(v)) === "near mint or better") ||
    values[0] ||
    null;

  return {
    conditionApi: target.api,
    conditionId: String(itemCondition.conditionId || target.conditionId),
    itemConditionFound: true,
    descriptorRequired: true,
    descriptorNameId: String(descriptor?.conditionDescriptorId || ""),
    descriptorName: String(descriptor?.conditionDescriptorName || ""),
    descriptorValueId: String(resolvedValue?.conditionDescriptorValueId || ""),
    descriptorValue: descriptorValueName(resolvedValue),
    graded: false,
    availableDescriptorValues: values.map(v => ({
      id: String(v?.conditionDescriptorValueId || ""),
      value: descriptorValueName(v)
    })),
    message: resolvedValue
      ? "Ungraded trading-card condition descriptor resolved from live eBay metadata."
      : "Card Condition was found, but eBay returned no usable descriptor value."
  };
}

async function handleResolveListing(request, env) {
  const url = new URL(request.url);
  const marketplace = String(url.searchParams.get("marketplace_id") || "EBAY_GB").trim();
  const q = String(url.searchParams.get("q") || "").trim();
  const conditionApi = String(url.searchParams.get("condition_api") || "USED_VERY_GOOD").trim();

  if (!q) {
    return json({ ok: false, error: "query_required", message: "q is required." }, 400);
  }

  const tree = await taxonomyFetch(
    env,
    "/commerce/taxonomy/v1/get_default_category_tree_id?marketplace_id=" +
      encodeURIComponent(marketplace)
  );
  const treeId = String(tree?.categoryTreeId || "");
  if (!treeId) {
    throw new Error("eBay did not return a category tree ID for " + marketplace + ".");
  }

  const suggestionsPayload = await taxonomyFetch(
    env,
    "/commerce/taxonomy/v1/category_tree/" +
      encodeURIComponent(treeId) +
      "/get_category_suggestions?q=" +
      encodeURIComponent(q)
  );

  const rawSuggestions = Array.isArray(suggestionsPayload?.categorySuggestions)
    ? suggestionsPayload.categorySuggestions
    : [];

  const suggestions = rawSuggestions.slice(0, 5).map(s => ({
    categoryId: String(s?.category?.categoryId || ""),
    categoryName: String(s?.category?.categoryName || ""),
    ancestors: Array.isArray(s?.categoryTreeNodeAncestors)
      ? s.categoryTreeNodeAncestors
          .map(a => String(a?.categoryName || a?.category?.categoryName || ""))
          .filter(Boolean)
      : []
  })).filter(s => s.categoryId);

  const category = suggestions[0] || null;
  if (!category) {
    return json({
      ok: false,
      error: "no_category_suggestion",
      message: "eBay returned no category suggestion for this item.",
      query: q
    }, 422);
  }

  const aspectPayload = await taxonomyFetch(
    env,
    "/commerce/taxonomy/v1/category_tree/" +
      encodeURIComponent(treeId) +
      "/get_item_aspects_for_category?category_id=" +
      encodeURIComponent(category.categoryId)
  );

  const allAspects = Array.isArray(aspectPayload?.aspects)
    ? aspectPayload.aspects
    : [];

  const requiredAspects = allAspects
    .filter(a => a?.aspectConstraint?.aspectRequired === true)
    .map(a => ({
      name: String(a?.localizedAspectName || ""),
      mode: String(a?.aspectConstraint?.aspectMode || ""),
      values: Array.isArray(a?.aspectValues)
        ? a.aspectValues
            .slice(0, 100)
            .map(v => String(v?.localizedValue || ""))
            .filter(Boolean)
        : []
    }))
    .filter(a => a.name);

  const filter = encodeURIComponent("categoryIds:{" + category.categoryId + "}");
  const conditionResult = await ebayFetch(
    env,
    "/sell/metadata/v1/marketplace/" +
      encodeURIComponent(marketplace) +
      "/get_item_condition_policies?filter=" +
      filter
  );

  if (!conditionResult.ok) {
    return json({
      ok: false,
      error: "condition_metadata_failed",
      message: "eBay Metadata API did not return condition policy data.",
      status: conditionResult.status,
      data: conditionResult.data,
      category
    }, conditionResult.status || 502);
  }

  const conditionPayload = conditionResult.data || {};
  const policies = Array.isArray(conditionPayload?.itemConditionPolicies)
    ? conditionPayload.itemConditionPolicies
    : [];

  const conditionPolicy =
    policies.find(p => String(p?.categoryId || "") === category.categoryId) ||
    policies[0] ||
    null;

  const condition = resolveConditionMetadata(conditionPolicy, conditionApi);

  return json({
    ok: true,
    engine: "gengrail-listing-resolver-v2",
    marketplace,
    query: q,
    categoryTreeId: treeId,
    category,
    suggestions,
    requiredAspects,
    condition,
    ready: Boolean(
      category.categoryId &&
      (
        condition.descriptorRequired === false ||
        (condition.descriptorNameId && condition.descriptorValueId)
      )
    )
  });
}


async function handleUploadImage(request, env) {
  let payload;
  try {
    const raw = await request.text();
    if (!raw) throw new Error("empty request body");
    payload = JSON.parse(raw);
  } catch (err) {
    return json({
      ok:false,
      error:"invalid_image_payload",
      message:"The Gengrail image bridge could not read the image payload.",
      detail:String(err?.message || err || "unknown parse error")
    }, 400);
  }

  const filename = String(payload?.filename || "gengrail-card.jpg");
  const contentType = String(payload?.contentType || "image/jpeg");
  const dataBase64 = String(payload?.dataBase64 || "");

  if (!dataBase64) {
    return json({ ok:false, error:"image_required", message:"The uploaded image was empty." }, 400);
  }

  let bytes;
  try {
    const binary = atob(dataBase64);
    bytes = new Uint8Array(binary.length);
    for (let i=0;i<binary.length;i++) bytes[i]=binary.charCodeAt(i);
  } catch {
    return json({ ok:false, error:"invalid_image_encoding", message:"The image could not be decoded." }, 400);
  }

  if (!bytes.byteLength) {
    return json({ ok:false, error:"image_required", message:"The uploaded image was empty." }, 400);
  }

  const image = new File([bytes], filename, { type: contentType });

  // eBay receives the exact multipart/form-data upload it requires.
  const token = await getAccessToken(env);
  const form = new FormData();
  form.set("image", image, filename);

  const res = await fetch(EBAY_MEDIA_API + "/image/create_image_from_file", {
    method: "POST",
    headers: {
      "authorization": "Bearer " + token,
      "accept": "application/json"
    },
    body: form
  });

  const text = await res.text();
  let data = null;
  if (text) {
    try { data = JSON.parse(text); } catch { data = { raw:text }; }
  }

  if (!res.ok) {
    return json({
      ok:false,
      error:"ebay_image_upload_failed",
      status:res.status,
      message:"eBay Picture Services rejected the image upload.",
      data
    }, res.status || 502);
  }

  const location = res.headers.get("location") || "";
  const imageId = location ? location.split("/").filter(Boolean).pop() : "";
  const imageUrl = String(data?.imageUrl || data?.maxDimensionImageUrl || "");

  if (!imageUrl) {
    return json({
      ok:false,
      error:"ebay_image_url_missing",
      message:"eBay accepted the image but did not return an EPS image URL.",
      imageId,
      data
    }, 502);
  }

  return json({
    ok:true,
    imageId,
    imageUrl,
    maxDimensionImageUrl:String(data?.maxDimensionImageUrl || ""),
    expirationDate:data?.expirationDate || null
  });
}

function cleanAspectMap(aspects) {
  const out = {};
  if (!aspects || typeof aspects !== "object") return out;
  for (const [name, raw] of Object.entries(aspects)) {
    const key = String(name || "").trim();
    if (!key) continue;
    const values = (Array.isArray(raw) ? raw : [raw])
      .map(v => String(v || "").trim())
      .filter(Boolean);
    if (values.length) out[key] = values;
  }
  return out;
}

async function handlePrepareListing(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok:false, error:"invalid_json", message:"Request body must be valid JSON." }, 400);
  }

  const sku = String(body?.sku || "").trim();
  const categoryId = String(body?.categoryId || "").trim();
  const title = String(body?.title || "").trim().slice(0, 80);
  const description = String(body?.description || "").trim();
  const condition = String(body?.condition || "").trim();
  const quantity = Math.max(1, Math.floor(Number(body?.quantity || 1)));
  const imageUrls = Array.isArray(body?.imageUrls)
    ? body.imageUrls.map(x => String(x || "").trim()).filter(Boolean)
    : [];
  const aspects = cleanAspectMap(body?.aspects);

  const settings = body?.settings || {};
  const marketplaceId = String(settings.marketplaceId || "EBAY_GB");
  const merchantLocationKey = String(settings.merchantLocationKey || "").trim();
  const paymentPolicyId = String(settings.paymentPolicyId || "").trim();
  const fulfillmentPolicyId = String(settings.fulfillmentPolicyId || "").trim();
  const returnPolicyId = String(settings.returnPolicyId || "").trim();
  const currency = String(settings.currency || "GBP").trim();
  const format = String(settings.format || "FIXED_PRICE").trim();
  const listingDuration = String(settings.listingDuration || "GTC").trim();
  const price = Number(body?.price || 0);

  const missing = [];
  if (!sku) missing.push("sku");
  if (!categoryId) missing.push("categoryId");
  if (!title) missing.push("title");
  if (!description) missing.push("description");
  if (!condition) missing.push("condition");
  if (!Object.keys(aspects).length) missing.push("aspects");
  if (!imageUrls.length) missing.push("imageUrls");
  if (!(price > 0)) missing.push("price");
  if (!merchantLocationKey) missing.push("merchantLocationKey");
  if (!paymentPolicyId) missing.push("paymentPolicyId");
  if (!fulfillmentPolicyId) missing.push("fulfillmentPolicyId");
  if (!returnPolicyId) missing.push("returnPolicyId");

  if (missing.length) {
    return json({
      ok:false,
      error:"listing_not_ready",
      message:"The listing is missing required publishing data.",
      missing
    }, 400);
  }

  const conditionDescriptors = [];
  const descriptorName = String(body?.conditionDescriptorName || "").trim();
  const descriptorValue = String(body?.conditionDescriptorValue || "").trim();
  if (descriptorName && descriptorValue) {
    conditionDescriptors.push({
      name: descriptorName,
      values: [descriptorValue]
    });
  }

  const inventoryPayload = {
    availability: {
      shipToLocationAvailability: { quantity }
    },
    condition,
    ...(conditionDescriptors.length ? { conditionDescriptors } : {}),
    product: {
      title,
      description,
      aspects,
      imageUrls
    }
  };

  const inventory = await ebayFetch(
    env,
    "/sell/inventory/v1/inventory_item/" + encodeURIComponent(sku),
    { method:"PUT", body:JSON.stringify(inventoryPayload) }
  );

  if (!inventory.ok) {
    return json({
      ok:false,
      stage:"inventory_item",
      error:"inventory_item_failed",
      status:inventory.status,
      message:"eBay rejected the inventory item.",
      data:inventory.data
    }, inventory.status || 502);
  }

  const offerPayload = {
    sku,
    marketplaceId,
    format,
    categoryId,
    availableQuantity: quantity,
    merchantLocationKey,
    listingPolicies: {
      paymentPolicyId,
      fulfillmentPolicyId,
      returnPolicyId
    },
    pricingSummary: {
      price: {
        value: price.toFixed(2),
        currency
      }
    },
    listingDuration
  };

  let offer;
  const existingOfferId = String(body?.offerId || "").trim();
  if (existingOfferId) {
    offer = await ebayFetch(
      env,
      "/sell/inventory/v1/offer/" + encodeURIComponent(existingOfferId),
      { method:"PUT", body:JSON.stringify(offerPayload) }
    );
    if (!offer.ok) {
      return json({
        ok:false,
        stage:"offer_update",
        error:"offer_update_failed",
        status:offer.status,
        message:"The inventory item was accepted, but eBay rejected the existing offer update.",
        data:offer.data
      }, offer.status || 502);
    }
    return json({
      ok:true,
      prepared:true,
      sku,
      offerId:existingOfferId,
      inventoryStatus:inventory.status,
      offerStatus:offer.status,
      imageUrls
    });
  }

  offer = await ebayFetch(
    env,
    "/sell/inventory/v1/offer",
    { method:"POST", body:JSON.stringify(offerPayload) }
  );

  if (!offer.ok) {
    return json({
      ok:false,
      stage:"offer_create",
      error:"offer_create_failed",
      status:offer.status,
      message:"The inventory item was accepted, but eBay rejected the offer.",
      data:offer.data
    }, offer.status || 502);
  }

  const offerId = String(offer?.data?.offerId || "");
  if (!offerId) {
    return json({
      ok:false,
      stage:"offer_create",
      error:"offer_id_missing",
      message:"eBay accepted the offer but did not return an offerId.",
      data:offer.data
    }, 502);
  }

  return json({
    ok:true,
    prepared:true,
    sku,
    offerId,
    inventoryStatus:inventory.status,
    offerStatus:offer.status,
    imageUrls
  });
}

async function handlePublishListing(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok:false, error:"invalid_json", message:"Request body must be valid JSON." }, 400);
  }

  const offerId = String(body?.offerId || "").trim();
  if (!offerId) {
    return json({ ok:false, error:"offer_id_required", message:"offerId is required." }, 400);
  }

  const published = await ebayFetch(
    env,
    "/sell/inventory/v1/offer/" + encodeURIComponent(offerId) + "/publish",
    { method:"POST" }
  );

  if (!published.ok) {
    return json({
      ok:false,
      stage:"publish",
      error:"publish_failed",
      status:published.status,
      message:"eBay rejected the publish request.",
      data:published.data
    }, published.status || 502);
  }

  const listingId = String(published?.data?.listingId || "");
  return json({
    ok:true,
    published:true,
    offerId,
    listingId,
    data:published.data
  });
}

async function browseFetch(env, path) {
  const token = await getAppAccessToken(env);
  const res = await fetch(EBAY_API + path, {
    method: "GET",
    headers: {
      "authorization": "Bearer " + token,
      "accept": "application/json",
      "accept-language": "en-GB",
      "x-ebay-c-marketplace-id": "EBAY_GB"
    }
  });
  const text = await res.text();
  let data = null;
  if (text) { try { data = JSON.parse(text); } catch { data = { raw: text }; } }
  return { ok: res.ok, status: res.status, data };
}

async function handleGradedMarket(request, env) {
  let body;
  try { body = await request.json(); }
  catch { return json({ ok:false, error:"invalid_json", message:"Request body must be valid JSON." }, 400); }

  const cardName = String(body?.cardName || "").trim();
  const cardNumber = String(body?.cardNumber || "").trim();
  const grader = String(body?.grader || "").trim();
  const grade = String(body?.grade || "").trim();
  const setName = String(body?.setName || "").trim();
  const language = String(body?.language || "").trim();
  const missing = [];
  if (!cardName) missing.push("cardName");
  if (!cardNumber) missing.push("cardNumber");
  if (!grader) missing.push("grader");
  if (!grade) missing.push("grade");
  if (missing.length) return json({ ok:false, error:"graded_identity_required", missing }, 400);

  const query = [cardName, cardNumber, grader, grade, language, "Pokemon"].filter(Boolean).join(" ");
  const params = new URLSearchParams();
  params.set("q", query);
  params.set("limit", "50");
  params.set("filter", "buyingOptions:{FIXED_PRICE}");
  const ebay = await browseFetch(env, "/buy/browse/v1/item_summary/search?" + params.toString());
  if (!ebay.ok) {
    return json({ ok:false, error:"ebay_browse_failed", status:ebay.status, message:"eBay current-listing search failed.", data:ebay.data }, ebay.status || 502);
  }

  const itemSummaries = Array.isArray(ebay.data?.itemSummaries) ? ebay.data.itemSummaries.map(x => ({
    itemId: String(x?.itemId || ""),
    title: String(x?.title || ""),
    price: x?.price || null,
    itemWebUrl: String(x?.itemWebUrl || ""),
    condition: String(x?.condition || ""),
    buyingOptions: Array.isArray(x?.buyingOptions) ? x.buyingOptions : [],
    seller: x?.seller ? { username: String(x.seller.username || ""), feedbackPercentage: String(x.seller.feedbackPercentage || "") } : null,
    image: x?.image?.imageUrl ? { imageUrl: String(x.image.imageUrl) } : null,
    itemLocation: x?.itemLocation || null
  })) : [];

  return json({
    ok:true,
    source:"eBay Browse API · active EBAY_GB listings",
    evidenceType:"current_active_asking_prices",
    query,
    identity:{ cardName, cardNumber, setName, language, grader, grade },
    total:Number(ebay.data?.total || itemSummaries.length || 0),
    itemSummaries
  });
}


async function handleOpportunitySearch(request, env) {
  const url = new URL(request.url);
  const q = String(url.searchParams.get("q") || "").trim();
  const limit = Math.min(100, Math.max(1, Number(url.searchParams.get("limit") || 50)));
  const maxPrice = Math.max(0, Number(url.searchParams.get("max_price") || 0));
  if (!q) return json({ ok:false, error:"query_required", message:"q is required." }, 400);

  const params = new URLSearchParams();
  params.set("q", q);
  params.set("limit", String(limit));
  const filters = ["buyingOptions:{FIXED_PRICE}"];
  if (maxPrice > 0) filters.push(`price:[..${maxPrice.toFixed(2)}]`, "priceCurrency:GBP");
  params.set("filter", filters.join(","));

  const ebay = await browseFetch(env, "/buy/browse/v1/item_summary/search?" + params.toString());
  if (!ebay.ok) {
    return json({ ok:false, error:"ebay_browse_failed", status:ebay.status, message:"eBay current-listing opportunity search failed.", data:ebay.data }, ebay.status || 502);
  }

  const itemSummaries = Array.isArray(ebay.data?.itemSummaries) ? ebay.data.itemSummaries.map(x => ({
    itemId: String(x?.itemId || ""),
    title: String(x?.title || ""),
    price: x?.price || null,
    itemWebUrl: String(x?.itemWebUrl || ""),
    condition: String(x?.condition || ""),
    buyingOptions: Array.isArray(x?.buyingOptions) ? x.buyingOptions : [],
    seller: x?.seller ? {
      username: String(x.seller.username || ""),
      feedbackPercentage: String(x.seller.feedbackPercentage || ""),
      feedbackScore: Number(x.seller.feedbackScore || 0)
    } : null,
    image: x?.image?.imageUrl ? { imageUrl: String(x.image.imageUrl) } : null,
    itemLocation: x?.itemLocation || null,
    shippingOptions: Array.isArray(x?.shippingOptions) ? x.shippingOptions.map(y => ({
      shippingCost: y?.shippingCost || null,
      shippingCostType: String(y?.shippingCostType || "")
    })) : []
  })) : [];

  return json({
    ok:true,
    engine:"gengrail-opportunity-search-v1",
    source:"eBay Browse API · active EBAY_GB listings",
    evidenceType:"current_active_asking_prices",
    query:q,
    total:Number(ebay.data?.total || itemSummaries.length || 0),
    itemSummaries
  });
}

async function handleOrders(request, env) {
  const url = new URL(request.url);
  const limit = Math.min(50, Math.max(1, Number(url.searchParams.get("limit") || 20)));
  const ebay = await ebayFetch(env, "/sell/fulfillment/v1/order?limit=" + limit);
  return json({
    ok: ebay.ok,
    status: ebay.status,
    data: ebay.data
  }, ebay.ok ? 200 : ebay.status || 502);
}

export default {
  async fetch(request, env) {
    const missing = requireConfig(env);
    if (missing.length) {
      return json({
        ok: false,
        error: "configuration_missing",
        missing
      }, 500);
    }

    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(env) });
    }

    try {
      let response;

      if (url.pathname === "/" || url.pathname === "/health") {
        response = json({
          ok: true,
          service: "Gengrail eBay Production Backend",
          environment: "production",
          build: "v19.4.3-condition-descriptor-resolver-v2"
        });
      } else if (url.pathname === "/oauth/start" && request.method === "GET") {
        // Navigation endpoint: no CORS needed for the redirect itself.
        return handleStart(request, env);
      } else if (url.pathname === "/ebay/callback" && request.method === "GET") {
        return handleCallback(request, env);
      } else if (url.pathname === "/api/ebay/opportunities/search" && request.method === "GET") {
        response = await handleOpportunitySearch(request, env);
      } else if (url.pathname === "/api/ebay/graded-market" && request.method === "POST") {
        response = await handleGradedMarket(request, env);
      } else if (url.pathname === "/api/ebay/status" && request.method === "GET") {
        response = await handleStatus(env);
      } else if (url.pathname === "/api/ebay/policies" && request.method === "GET") {
        response = await handlePolicies(env);
      } else if (url.pathname === "/api/ebay/resolve-listing" && request.method === "GET") {
        response = await handleResolveListing(request, env);
      } else if (url.pathname === "/api/ebay/media/image" && request.method === "POST") {
        response = await handleUploadImage(request, env);
      } else if (url.pathname === "/api/ebay/listing/prepare" && request.method === "POST") {
        response = await handlePrepareListing(request, env);
      } else if (url.pathname === "/api/ebay/listing/publish" && request.method === "POST") {
        response = await handlePublishListing(request, env);
      } else if (url.pathname === "/api/ebay/inventory-locations" && request.method === "GET") {
        response = await handleInventoryLocations(env);
      } else if (url.pathname === "/api/ebay/inventory-location" && request.method === "POST") {
        response = await handleCreateInventoryLocation(request, env);
      } else if (url.pathname === "/api/ebay/orders" && request.method === "GET") {
        response = await handleOrders(request, env);
      } else if (url.pathname === "/api/ebay/disconnect" && request.method === "POST") {
        response = await handleDisconnect(env);
      } else {
        response = json({ ok: false, error: "not_found" }, 404);
      }

      return withCors(response, env);
    } catch (err) {
      return withCors(json({
        ok: false,
        error: "worker_error",
        message: String(err?.message || err)
      }, 500), env);
    }
  }
};
