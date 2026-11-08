<h1 align="center">subfinder + ndxer</h1>

<p align="center">
<b>Every hostname ndxer's DNS database holds under a domain, plus the other domains that belong to the same owner.</b><br>
<a href="#quick-start">Quick start</a> •
<a href="#what-you-get">What you get</a> •
<a href="#recipes">Recipes</a> •
<a href="#flags">Flags</a> •
<a href="#units-plans-and-rate-limits">Units and plans</a> •
<a href="#troubleshooting">Troubleshooting</a>
</p>

This is [subfinder](https://github.com/projectdiscovery/subfinder) with [ndxer](https://ndxer.com/) built in. ndxer
is a DNS database you query over an API. Give this build a domain and an ndxer API key, and it does two things stock
subfinder can't:

1. **The `ndxer` source** lists every hostname ndxer holds under the domain. That covers names with DNS records of
   their own, and also hosts that other records point at: CNAME targets, mail servers, name servers, SPF includes
   and SOA primaries. Names such as `mx1.example.com` or `ns2.example.com` often appear in no other source.
2. **Related scope.** Stock subfinder only returns names under the domain you type. With an ndxer key, this build
   first asks ndxer which other domains belong to the same owner, such as `example.net` or `example-cdn.com`, and
   enumerates those as well. This is **on by default**. Every run prints a banner that says what was added and why,
   what was left out, and what it cost.

Everything else works the same as upstream subfinder: every other source, every flag, the output formats. The ndxer
source and related scope run alongside the rest.

---

## Quick start

### 1. Get an ndxer API key

1. Create an account at **https://ndxer.com/accounts/signup/**. The Free plan works, but read
   [units and plans](#units-plans-and-rate-limits) first.
2. Open **https://ndxer.com/app/api-keys/** and create a key.
3. Copy it straight away, because it is shown only once. It looks like `ndx_live_<8 characters>_<43 characters>`.

Check that the key works. This call is free:

```sh
export NDXER_API_KEY='ndx_live_...'
curl -s -H "Authorization: Bearer $NDXER_API_KEY" https://api.ndxer.com/v1/me/
```

You should see your `plan_key` and a `usage` block with `remaining` units. A `401 unauthenticated` means the key
was mistyped or revoked.

### 2. Install

You need **Go 1.26 or newer** (`go version`).

```sh
go install -v github.com/southax/subfinder/v2/cmd/subfinder@ndxer
```

- Use **`@ndxer`, not `@latest`.** This fork carries upstream's version tags, so `@latest` installs a plain upstream
  release with no ndxer in it.
- The binary is called `subfinder` and lands in `$(go env GOPATH)/bin`. It **replaces** any upstream subfinder
  installed there.
- **Don't run `subfinder -up`.** The self-updater downloads upstream's release and removes ndxer. To update this
  build, run the `go install` line again.

Or build from source:

```sh
git clone -b ndxer https://github.com/southax/subfinder && cd subfinder
go build -o subfinder ./cmd/subfinder
```

Check that the build includes ndxer:

```sh
subfinder -ls | grep ndxer          # prints: ndxer *    (the * means it needs a key)
```

### 3. Give subfinder the key

subfinder reads `NDXER_API_KEY` from the environment by itself:

```sh
export NDXER_API_KEY='ndx_live_...'       # add this to ~/.bashrc or ~/.zshrc to keep it
```

Or put it in subfinder's provider config, `~/.config/subfinder/provider-config.yaml`. The file is created on first
run. Pass another path with `-pc`.

```yaml
ndxer:
  - ndx_live_KEYID_SECRET
```

With several keys listed, the ndxer source picks one at random for each domain, and the related lookup uses the
first. You only need one of the two: the environment variable or the config file.

### 4. First run

Start with ndxer on its own, so you can see exactly what it contributes:

```sh
subfinder -d example.com -s ndxer -stats
```

What a successful run looks like:

- Hostnames are printed on **stdout**, one per line.
- The **ndxer related scope** banner is printed on **stderr** (see the next section). It says which domains were
  added.
- A statistics table is printed at the end, with an `ndxer` row showing `Requests` of 1 or more and `Errors` of 0.

Then run with every source:

```sh
subfinder -d example.com -o example.com.txt
```

ndxer is a default source, so it runs alongside the free sources and any others you have keys for.

---

## What you get

### Hostnames under the domain

The `ndxer` source makes one paged lookup per domain. Every host comes back once, lower-cased and deduplicated. It
follows pages until the list ends, so you get the whole list and not a sample.

### Related scope: the banner

For every domain you pass, the banner on stderr looks like this. The format is real; the domains here are
placeholders.

```text
==============================================================================
ndxer related scope for example.com
  Added 9 domains ndxer links to the same owner (9 subject), enumerated with all selected sources:
    6 share mx_host mx1.example-mail.com + verify_token example-site-verification=Q2xhdWRlIGV4YW1wbGUgdG9rZW4
      example.net example.org example-cdn.com example-status.com example-shop.com example-labs.com
    2 share verify_token example-site-verification=Q2xhdWRlIGV4YW1wbGUgdG9rZW4
      example-careers.com example-events.com
    1 share mx_host mx1.example-mail.com + mx_set 0F3A9C2B7D41E865
      example-ventures.com
  NOT added: 12 review domains (weaker evidence of the same owner). Include them with: -ndxer-related-classes subject,review
  NOT added: 4 shared signals belong to infrastructure providers, not to the subject; never added.
  ndxer source: about 1 unit per page for each added domain (9 domains), charged on top of the units below.
  Units charged by the related lookup: 5 (1 page)
  Turn off: -no-ndxer-related
  Inspect the evidence:
    curl -s -H "Authorization: Bearer $NDXER_API_KEY" "https://api.ndxer.com/v1/related/?q=example.com"
    https://ndxer.com/app/investigations/?q=example.com
==============================================================================
```

How to read it:

| Line | Meaning |
|---|---|
| **Added … (subject)** | Domains ndxer proposes as the owner's own. They are enumerated with **every source you selected**, not only ndxer, so their hostnames show up in your output. |
| **N share …** | The added domains grouped by the values they share with your domain (largest group first), with up to 6 examples per group. Long values are cut at 60 characters. `-oJ` gives every domain's full values. |
| **NOT added: review** | Weaker evidence of the same owner. They are counted here but not enumerated. Add them with `-ndxer-related-classes subject,review`. |
| **NOT added: shared signals** | Values that belong to infrastructure providers, such as a hosting company's name servers. They are never used to add domains. |
| **Units** | What the related lookup cost, and a reminder that each added domain also costs at least one ndxer source lookup. |
| **Inspect the evidence** | The same answer as raw JSON, or in ndxer's investigation page, with the shared values behind every match. |

A **subject** class is a proposal, not proof of ownership. Before you treat an added domain as in scope for a test,
open the evidence link. **The banner always goes to stderr**, even with `-silent`, so `stdout` stays a clean list of
hostnames for pipes.

### JSON output tells you where each host came from

With `-oJ`, hosts under an added domain carry four extra fields:

```json
{"host":"api.example.net","input":"example.net","source":"ndxer","ndxer_seed":"example.com","ndxer_class":"subject","ndxer_why":"Shares the verification token example-site-verification=Q2xhdWRlIGV4YW1wbGUgdG9rZW4, issued to one account.","ndxer_evidence":[{"kind":"mx_host","key":"mx1.example-mail.com","n":7},{"kind":"verify_token","key":"example-site-verification=Q2xhdWRlIGV4YW1wbGUgdG9rZW4","n":9}]}
```

- `ndxer_seed`: the domain you asked for, which led to this host.
- `ndxer_class`: the class its domain was added as (`subject` or `review`).
- `ndxer_why`: ndxer's most decisive reason for the match, in ndxer's own words, exactly as the
  [related API](https://ndxer.com/docs/) returns it. Left out when ndxer gives no reason.
- `ndxer_evidence`: the values the domain shares with `ndxer_seed`. `kind` is the type of value, `key` the value
  itself, and `n` how many domains share it. `provider` is added when the value belongs to a named provider.
  Shared first labels (`name_label`) are listed only when they are the only evidence.

With `-cs`, the `sources` array and these fields appear together.

Hosts under the domain you typed have none of these fields.

---

## Recipes

```sh
# Everything: every source, ndxer included, plus related scope
subfinder -d example.com -o all.txt

# Only ndxer (related scope still on)
subfinder -d example.com -s ndxer

# Stock subfinder scope (only names under example.com) plus the ndxer source
subfinder -d example.com -no-ndxer-related

# Widest scope: add review-class domains too
subfinder -d example.com -ndxer-related-classes subject,review

# Many domains from a file; each line gets its own banner
subfinder -dL domains.txt -o out.txt

# JSON lines with the source of every host, then split what you typed from what ndxer added
subfinder -d example.com -oJ -cs -o out.jsonl
jq -r 'select(.ndxer_seed == null) | .host' out.jsonl     # under example.com
jq -r 'select(.ndxer_seed != null) | .host' out.jsonl     # under domains ndxer added

# Clean stdout for pipes (the banner stays on stderr)
subfinder -d example.com -silent | dnsx -silent | httpx -silent

# Keep the banners for later
subfinder -d example.com -o out.txt 2> ndxer-banner.txt

# Cap ndxer's hosts per domain to bound units
subfinder -d example.com -s ndxer -max-results 500
```

---

## Flags

These flags are added by this build:

| Flag | Default | What it does |
|---|---|---|
| `-ndxer-related-classes` | `subject` | Which related domains to add: `subject`, or `subject,review` for the widest scope. `infrastructure` is refused, because those domains belong to a provider. |
| `-no-ndxer-related` | off | Turns related scope off. You get stock subfinder scope, with the ndxer source still running. |

These upstream flags matter most when you use ndxer:

| Flag | Use with ndxer |
|---|---|
| `-s ndxer` | Run only ndxer, or list it with others: `-s ndxer,crtsh`. |
| `-es ndxer` | Exclude ndxer and keep every other source. Related scope still runs while a key is set; add `-no-ndxer-related` to stop it too. |
| `-rls ndxer=10/m` | Rate-limit ndxer requests to your plan's requests per minute (see below). |
| `-max-results N` | Stop each source after N hosts per domain. This bounds ndxer's units. |
| `-pc file` | Provider config file holding the `ndxer:` key. |
| `-oJ`, `-cs` | JSON lines output, and which source found each host. |
| `-stats` | Per-source table at the end. The quickest way to see that ndxer ran with no errors. |
| `-silent` | Hostnames only on stdout. The banner still goes to stderr. |
| `-duc` | Skip the update check. That check compares against upstream releases, not this build. |

Everything else is upstream's: run `subfinder -h`, or read
[upstream's README](https://github.com/projectdiscovery/subfinder#usage).

---

## Units, plans and rate limits

Every ndxer request costs units from your monthly allowance. Plans differ in volume, not features: every plan
includes both lookups this build uses.

| Plan | Units / month | Hosts per page | Requests / minute | Suggested `-rls` |
|---|--:|--:|--:|---|
| Free | 250 | 25 | 10 | `-rls ndxer=10/m` |
| Developer | 10,000 | 250 | 60 | `-rls ndxer=60/m` |
| Team | 100,000 | 1,000 | 300 | `-rls ndxer=3/s` |
| Business | 1,000,000 | 1,000 | 1,000 | `-rls ndxer=3/s` |

Set `-rls` on every plan, Business included. Without it, subfinder sends ndxer requests as fast as it can, and
bursts well under the per-minute limit can still be answered with HTTP 503. One subfinder process at
`-rls ndxer=3/s` ran 200 organisations without a single ndxer error; four processes on one key with no `-rls`
(about 40 requests in flight) got fast 503s. On Business you can raise the rate step by step while the `-stats`
table shows 0 ndxer errors.

`-rls` applies to one process. Several subfinder processes on the same key add up, so run one process with a
domain list (`-dL`) rather than many processes side by side, or split the rate between them.

`-rls ndxer=…` paces the hostnames source only, not the related lookup. The related lookup makes about one call
per domain you pass (more when its answer runs to several pages) and retries on its own.

**The source retries.** On HTTP 429 it waits the `Retry-After` the API sends; on 502, 503 and 504, and on a
response cut off before it ends, it retries with exponential backoff and jitter. It makes at most 5 attempts per
request and never waits more than 60 s at a time. Other errors, such as a bad key or an exhausted allowance, are
not retried. The related lookup retries the same way. Retries help with short bursts; they are not a substitute
for `-rls`.

Current plans and prices are at https://ndxer.com/pricing/. `GET /v1/me/` (free) shows how many units you have left.

What a run costs:

- **The ndxer source:** 1 unit per page, for every domain it runs on: the one you typed and every domain related
  scope adds. A domain with 2,000 hosts takes 80 pages on Free (25 hosts a page) but only 2 on Team (1,000 a page).
- **The related lookup:** once per domain you pass, 1 unit plus 1 per shared value scored on the first page (at
  most 8 units), then 1 unit for each further page. The banner prints the exact charge.
- **A domain ndxer is still looking up costs nothing extra to wait for.** For a domain it has not seen before, ndxer
  may answer "still looking it up" for a short while. Both lookups ask again until the answer is ready, for up to
  2 minutes per domain. Those repeats cost no units, though `-stats` counts each one as a request.
- **Large organisations add many domains.** In one real run, a well-known company's domain brought in **480 subject
  domains, and the run cost about 490 units**. That's more than a Free month. On Free, either start with
  `-no-ndxer-related` and turn related scope on for the domains you care about, or move to a larger plan.

**ndxer stops early rather than spend your allowance on a list it can't finish.** If the first page shows that
listing a domain would need more units than you have left this month, the source keeps that page (1 unit) and stops
with an error that gives both numbers. With `-max-results` set it does not stop early, since that flag already
bounds the spend. The related lookup stops the same way and says so in the banner.

---

## Troubleshooting

| You see | Cause | Fix |
|---|---|---|
| `The following sources were included but skipped... ndxer` | No key found | Set `NDXER_API_KEY`, or add `ndxer:` to the provider config ([step 3](#3-give-subfinder-the-key)). |
| `ndxer related lookup failed: unauthenticated: Invalid or revoked API key. (HTTP 401)` | Wrong or revoked key | Create a new key at https://ndxer.com/app/api-keys/ and check it with `/v1/me/`. |
| `quota_exceeded` in an error, or `kept the first page` | This month's units are used up | Wait for the period to end (the message gives the date), raise your plan, or use `-max-results` / `-no-ndxer-related`. |
| `rate_limited` / HTTP 429 | Requests per minute above your plan's limit | Add `-rls ndxer=<plan limit>/m` from the table above. |
| HTTP 503 or 429, or `gave up after 5 attempts` | Requests arrive faster than the API takes them, even after the retries | Lower `-rls ndxer=…` (for example to `3/s` or less) and run one subfinder process per key, with `-dL` for many domains. |
| `ndxer is still looking up example.com; run again shortly` | ndxer had not seen the domain before and was still looking it up after 2 minutes | Run the same command again in a few minutes. Waiting costs no units. |
| Related scope added nothing | ndxer has no subject domains for this owner | The banner still lists review domains. Try `-ndxer-related-classes subject,review`. |
| `subfinder -ls` doesn't list `ndxer` | You are running an upstream binary | Run `which subfinder`, then reinstall with `@ndxer` ([step 2](#2-install)). |

ndxer's API errors include a `request_id`. Quote it when you contact ndxer support.

To call the API directly, see the [API docs](https://ndxer.com/docs/) and the
[OpenAPI contract](https://api.ndxer.com/v1/openapi.json).

---

## About this build

- It is kept current with upstream subfinder's `dev` branch.
- **This build is not affiliated with or endorsed by ProjectDiscovery.** subfinder is their work, MIT-licensed; see
  [LICENSE.md](LICENSE.md). For every other source, its API keys, the full flag list, Docker images and using
  subfinder as a Go library, see [upstream's README](https://github.com/projectdiscovery/subfinder#readme).
