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
    "access-control-allow-headers": "content-type",
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

function conditionTarget(conditionApi = "USED_VERY_GOOD") {
  const api = String(conditionApi || "USED_VERY_GOOD").toUpperCase();
  if (api === "LIKE_NEW") {
    return {
      api,
      conditionId: "2750",
      descriptorName: "",
      descriptorValue: "",
      graded: true
    };
  }
  if (api === "NEW") {
    return {
      api,
      conditionId: "1000",
      descriptorName: "",
      descriptorValue: "",
      graded: false
    };
  }
  return {
    api: "USED_VERY_GOOD",
    conditionId: "4000",
    descriptorName: "Card Condition",
    descriptorValue: "Very Good",
    graded: false
  };
}

function descriptorValues(descriptor) {
  return Array.isArray(descriptor?.conditionDescriptorValues)
    ? descriptor.conditionDescriptorValues
    : [];
}

function resolveConditionMetadata(conditionPolicy, conditionApi) {
  const target = conditionTarget(conditionApi);
  const itemConditions = Array.isArray(conditionPolicy?.itemConditions)
    ? conditionPolicy.itemConditions
    : [];

  const itemCondition =
    itemConditions.find(c => String(c?.conditionId || "") === target.conditionId) ||
    itemConditions.find(c => normaliseText(c?.conditionDescription).includes(
      target.api === "USED_VERY_GOOD" ? "ungraded" :
      target.api === "LIKE_NEW" ? "graded" : "new"
    )) ||
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

  // Graded cards need Grader + Grade. The current Gengrail V1 draft model
  // only stores a single descriptor pair, so do not invent these values.
  if (target.graded) {
    return {
      conditionApi: target.api,
      conditionId: String(itemCondition.conditionId || target.conditionId),
      itemConditionFound: true,
      descriptorRequired: true,
      graded: true,
      descriptorNameId: "",
      descriptorName: "",
      descriptorValueId: "",
      descriptorValue: "",
      requiredDescriptors: descriptors.map(d => ({
        id: String(d?.conditionDescriptorId || ""),
        name: String(d?.conditionDescriptorName || ""),
        usage: String(d?.conditionDescriptorConstraint?.usage || ""),
        values: descriptorValues(d).map(v => ({
          id: String(v?.conditionDescriptorValueId || ""),
          value: String(v?.conditionDescriptorValue || "")
        }))
      })),
      message: "Graded card detected. Grader and Grade must be supplied before publishing."
    };
  }

  if (target.api === "NEW") {
    return {
      conditionApi: target.api,
      conditionId: String(itemCondition.conditionId || target.conditionId),
      itemConditionFound: true,
      descriptorRequired: false,
      graded: false,
      descriptorNameId: "",
      descriptorName: "",
      descriptorValueId: "",
      descriptorValue: "",
      message: "New condition resolved; no trading-card condition descriptor is required."
    };
  }

  const descriptor =
    descriptors.find(d => normaliseText(d?.conditionDescriptorName) === normaliseText(target.descriptorName)) ||
    descriptors.find(d => normaliseText(d?.conditionDescriptorHelpText).includes("ungraded")) ||
    null;

  if (!descriptor) {
    return {
      conditionApi: target.api,
      conditionId: String(itemCondition.conditionId || target.conditionId),
      itemConditionFound: true,
      descriptorRequired: true,
      graded: false,
      descriptorNameId: "",
      descriptorName: "",
      descriptorValueId: "",
      descriptorValue: "",
      message: "Card Condition descriptor was not returned for this category."
    };
  }

  const values = descriptorValues(descriptor);
  const desired = normaliseText(target.descriptorValue);
  const value =
    values.find(v => normaliseText(v?.conditionDescriptorValue) === desired) ||
    values.find(v => normaliseText(v?.conditionDescriptorValue).includes(desired)) ||
    null;

  const defaultValueId = String(
    descriptor?.conditionDescriptorConstraint?.defaultConditionDescriptorValueId || ""
  );

  const resolvedValue =
    value ||
    (defaultValueId
      ? values.find(v => String(v?.conditionDescriptorValueId || "") === defaultValueId)
      : null) ||
    null;

  return {
    conditionApi: target.api,
    conditionId: String(itemCondition.conditionId || target.conditionId),
    itemConditionFound: true,
    descriptorRequired: true,
    graded: false,
    descriptorNameId: String(descriptor?.conditionDescriptorId || ""),
    descriptorName: String(descriptor?.conditionDescriptorName || ""),
    descriptorValueId: String(resolvedValue?.conditionDescriptorValueId || ""),
    descriptorValue: String(resolvedValue?.conditionDescriptorValue || ""),
    availableDescriptorValues: values.map(v => ({
      id: String(v?.conditionDescriptorValueId || ""),
      value: String(v?.conditionDescriptorValue || "")
    })),
    message: resolvedValue
      ? "Trading-card condition descriptor resolved from live eBay metadata."
      : "Card Condition was found, but eBay did not return a matching Very Good descriptor value."
  };
}

function scoreCategorySuggestion(suggestion, query) {
  const categoryName = normaliseText(suggestion?.categoryName);
  const ancestors = Array.isArray(suggestion?.ancestors)
    ? suggestion.ancestors.map(normaliseText)
    : [];
  const haystack = [categoryName, ...ancestors].join(" ");
  const q = normaliseText(query);
  let score = 0;

  // eBay already ranks suggestions. These bonuses only protect trading-card
  // searches from drifting into accessories, boxes, lots, or unrelated items.
  if (haystack.includes("trading card")) score += 40;
  if (haystack.includes("collectible card game") || haystack.includes("ccg")) score += 35;
  if (categoryName.includes("individual") || categoryName.includes("single")) score += 25;
  if (q.includes("pokemon") || q.includes("pokémon")) {
    if (haystack.includes("pokemon") || haystack.includes("pokémon")) score += 30;
  }
  if (haystack.includes("accessor")) score -= 25;
  if (haystack.includes("sealed")) score -= 15;
  if (haystack.includes("box")) score -= 10;
  if (haystack.includes("lot")) score -= 8;
  return score;
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

  const suggestions = rawSuggestions.slice(0, 10).map((s, index) => ({
    rank: index + 1,
    categoryId: String(s?.category?.categoryId || ""),
    categoryName: String(s?.category?.categoryName || ""),
    ancestors: Array.isArray(s?.categoryTreeNodeAncestors)
      ? s.categoryTreeNodeAncestors
          .map(a => String(a?.categoryName || a?.category?.categoryName || ""))
          .filter(Boolean)
      : []
  })).filter(s => s.categoryId);

  if (!suggestions.length) {
    return json({
      ok: false,
      error: "no_category_suggestion",
      message: "eBay returned no category suggestion for this item.",
      query: q
    }, 422);
  }

  const category = suggestions
    .map(s => ({ ...s, gengrailScore: scoreCategorySuggestion(s, q) }))
    .sort((a, b) => (b.gengrailScore - a.gengrailScore) || (a.rank - b.rank))[0];

  const aspectPayload = await taxonomyFetch(
    env,
    "/commerce/taxonomy/v1/category_tree/" +
      encodeURIComponent(treeId) +
      "/get_item_aspects_for_category?category_id=" +
      encodeURIComponent(category.categoryId)
  );

  const allAspects = Array.isArray(aspectPayload?.aspects) ? aspectPayload.aspects : [];
  const requiredAspects = allAspects
    .filter(a => a?.aspectConstraint?.aspectRequired === true)
    .map(a => ({
      name: String(a?.localizedAspectName || ""),
      mode: String(a?.aspectConstraint?.aspectMode || ""),
      values: Array.isArray(a?.aspectValues)
        ? a.aspectValues.slice(0, 100)
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
    engine: "gengrail-listing-resolver-v1",
    marketplace,
    query: q,
    categoryTreeId: treeId,
    category: {
      categoryId: category.categoryId,
      categoryName: category.categoryName,
      ancestors: category.ancestors,
      sourceRank: category.rank,
      gengrailScore: category.gengrailScore
    },
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
          environment: "production"
        });
      } else if (url.pathname === "/oauth/start" && request.method === "GET") {
        // Navigation endpoint: no CORS needed for the redirect itself.
        return handleStart(request, env);
      } else if (url.pathname === "/ebay/callback" && request.method === "GET") {
        return handleCallback(request, env);
      } else if (url.pathname === "/api/ebay/status" && request.method === "GET") {
        response = await handleStatus(env);
      } else if (url.pathname === "/api/ebay/policies" && request.method === "GET") {
        response = await handlePolicies(env);
      } else if (url.pathname === "/api/ebay/resolve-listing" && request.method === "GET") {
        response = await handleResolveListing(request, env);
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
