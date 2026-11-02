const express = require("express");
const cheerio = require("cheerio");
const dns = require("dns").promises;
const net = require("net");
const path = require("path");

const app = express();
app.use(express.static(path.join(__dirname, "public")));

// Block requests to private/internal addresses so the proxy can't be
// used to poke at servers it shouldn't reach.
function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number);
    return (
      a === 0 || a === 10 || a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168)
    );
  }
  if (net.isIPv6(ip)) {
    const l = ip.toLowerCase();
    return l === "::1" || l.startsWith("fc") || l.startsWith("fd") ||
           l.startsWith("fe80") || l.startsWith("::ffff:");
  }
  return true;
}

async function checkUrl(raw) {
  const u = new URL(raw);
  if (!["http:", "https:"].includes(u.protocol)) throw new Error("Only http/https allowed");
  const addrs = await dns.lookup(u.hostname, { all: true });
  if (addrs.some((a) => isPrivateIp(a.address))) throw new Error("Blocked address");
  return u;
}

app.get("/proxy", async (req, res) => {
  try {
    let target = String(req.query.url || "").trim();
    if (!target) throw new Error("No URL given");
    if (!/^https?:\/\//i.test(target)) target = "https://" + target;
    const u = await checkUrl(target);

    const r = await fetch(u, {
      redirect: "manual",
      headers: {
        "user-agent": req.get("user-agent") || "Mozilla/5.0",
        accept: req.get("accept") || "*/*",
      },
    });

    // Follow redirects through the proxy
    const loc = r.headers.get("location");
    if (r.status >= 300 && r.status < 400 && loc) {
      const next = new URL(loc, u).href;
      return res.redirect("/proxy?url=" + encodeURIComponent(next));
    }

    const type = r.headers.get("content-type") || "";
    res.status(r.status);
    res.set("content-type", type);

    if (type.includes("text/html")) {
      const $ = cheerio.load(await r.text());
      const rewrite = (sel, attr) =>
        $(sel).each((_, el) => {
          const v = $(el).attr(attr);
          if (!v || /^(#|data:|javascript:|mailto:)/i.test(v)) return;
          try {
            $(el).attr(attr, "/proxy?url=" + encodeURIComponent(new URL(v, u).href));
          } catch {}
        });
      rewrite("a", "href");
      rewrite("img", "src");
      rewrite("script", "src");
      rewrite("link", "href");
      rewrite("form", "action");
      rewrite("source", "src");
      rewrite("iframe", "src");
      $("meta[http-equiv='refresh']").remove();
      res.send($.html());
    } else {
      res.send(Buffer.from(await r.arrayBuffer()));
    }
  } catch (e) {
    res.status(400).send("Error: " + e.message);
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("Proxy running on port " + port));
