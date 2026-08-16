from pathlib import Path

p = Path('worker.js')
s = p.read_text()

if 'async function handleOpportunitySearch(request, env)' not in s:
    marker = 'async function handleOrders(request, env) {'
    if marker not in s:
        raise SystemExit('handleOrders marker not found')
    fn = r'''
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

'''
    s = s.replace(marker, fn + marker, 1)

if '/api/ebay/opportunities/search' not in s:
    anchor = '      } else if (url.pathname === "/api/ebay/graded-market" && request.method === "POST") {\n'
    if anchor not in s:
        raise SystemExit('graded-market route anchor not found')
    route = '      } else if (url.pathname === "/api/ebay/opportunities/search" && request.method === "GET") {\n        response = await handleOpportunitySearch(request, env);\n'
    s = s.replace(anchor, route + anchor, 1)

p.write_text(s)
