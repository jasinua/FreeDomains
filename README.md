# Free Domains — GitOps Subdomain Registry

Get a free subdomain under our domain by opening a Pull Request. The entire process is automated via GitHub Actions and Cloudflare.

---

## How to Register a Subdomain

1. **Fork** this repository.
2. Inside the `domains/` folder, create a new file named `<your-subdomain>.json`.
   - The filename becomes your subdomain (e.g., `my-app.json` → `my-app.yourdomain.com`).
3. Fill the file using the schema below.
4. **Open a Pull Request** from your fork to this repository's `main` branch.
5. An automated check will validate your request. A maintainer will then review and merge it.
6. Once merged, your DNS record will be live within ~30 seconds.

---

## Domain Schema

Your JSON file must follow this exact structure:

```json
{
  "owner": {
    "username": "your-github-username",
    "email": "you@example.com"
  },
  "record": {
    "type": "CNAME",
    "value": "your-app.vercel.app"
  }
}
```

### Fields

| Field | Required | Description |
|---|---|---|
| `owner.username` | Yes | Your **exact** GitHub username. Must match the PR author. |
| `owner.email` | Yes | Contact email (can be private). |
| `record.type` | Yes | One of: `A`, `AAAA`, `CNAME` |
| `record.value` | Yes | The value for the DNS record (IP for A/AAAA, hostname for CNAME). |

### Allowed Record Types

| Type | Use Case | Example Value |
|---|---|---|
| `CNAME` | Point to a hostname (Vercel, Netlify, GitHub Pages, etc.) | `my-app.vercel.app` |
| `A` | Point to an IPv4 address | `76.76.21.21` |
| `AAAA` | Point to an IPv6 address | `2600:1f18:...` |

> **Note:** `NS`, `MX`, `TXT`, `CAA`, and `SOA` records are not supported to prevent abuse.

---

## Subdomain Naming Rules

- **Lowercase alphanumeric characters and hyphens only** (`a-z`, `0-9`, `-`)
- **Cannot start or end with a hyphen**
- **Length:** 1–63 characters
- **Must not be a reserved word** (see blocklist below)

### Reserved / Blocked Subdomains

The following prefixes are permanently reserved and cannot be registered:

`www`, `mail`, `api`, `dev`, `admin`, `auth`, `login`, `status`, `cdn`, `ns`, `ns1`, `ns2`, and many brand names (google, paypal, apple, etc.).

See [`scripts/validate.js`](scripts/validate.js) for the full blocklist.

---

## Limitations

- **One subdomain per GitHub account.** Each GitHub user may have at most one active subdomain.
- **No transferring:** You cannot change `owner.username` after registration. Delete and re-register instead.
- **No wildcard records** (`*`).
- **No private IPs:** A/AAAA records pointing to RFC 1918 / reserved address ranges are rejected.

---

## Updating Your Record

Open a new Pull Request modifying **only your own** `domains/<your-subdomain>.json`. The `owner.username` must still match your GitHub account.

## Deleting Your Subdomain

Open a PR that **deletes** your `domains/<your-subdomain>.json` file. Once merged, the DNS record will be removed automatically.

---

## Takedown Policy

We reserve the right to **immediately remove** any subdomain found to be:

- Hosting phishing pages, malware, or malicious content
- Impersonating brands, products, or individuals
- Sending spam or operating unsolicited bulk email
- Violating any applicable laws

Abuse reports: open an issue or email the maintainer directly.

There is **no appeal process** for subdomain removals due to malicious content.

---

## For Maintainers

### Repository Secrets Required

| Secret | Description |
|---|---|
| `CF_API_TOKEN` | Cloudflare API token with `Zone:DNS:Edit` on the target zone only |
| `CF_ZONE_ID` | The Cloudflare Zone ID for your domain |
| `BASE_DOMAIN` | Your root domain (e.g., `yourdomain.com`) |

### Cloudflare API Token Permissions

When creating the token in the Cloudflare dashboard, use these minimal permissions:
- **Permissions:** `Zone → DNS → Edit`
- **Zone Resources:** `Include → Specific Zone → <your domain>`

Do **not** use your Global API Key.

### PR Review Checklist

Before approving a PR, manually verify:
1. The target URL looks legitimate and not suspicious.
2. The subdomain name is not misleading or brand-impersonating.
3. The `owner.username` matches the GitHub account that opened the PR (the automated check does this too, but a second set of eyes helps).
