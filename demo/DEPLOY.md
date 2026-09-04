# Deploying the demo to Google Cloud Run

The demo is a stdlib Python server that shells out to `openssl` and `dig`. The
`Dockerfile` at the repo root packages it (adds `openssl` + `dnsutils`, `pip
installs` `reedsolo` for `fairoze-1` verification, and copies `samples/`). Cloud
Run's monthly free tier covers a demo's traffic; with `--min-instances 0` you
pay nothing at idle.

The `fairoze-1` sample tab needs no key or secret -- the samples are
pre-generated and verify against the public DNS record at
`3._watermark-text.demo.terryzink.com`.

## One-time setup

```bash
# install the gcloud CLI, then:
gcloud auth login
gcloud config set project YOUR_PROJECT_ID

gcloud services enable \
  run.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com \
  secretmanager.googleapis.com
```

## 1. Put the demo signing key(s) in Secret Manager

Use **dedicated throwaway keys** whose `_watermark-text` records you control --
never a real signing key. If one is leaked you just rotate the DNS `p=`.

```bash
gcloud secrets create demo-wm-key \
  --data-file=demo/keys/1._watermark-text.demo.terryzink.com.private.pem

# a second key (published with a=tzsataitw-2) -- optional
gcloud secrets create demo-wm-key-2 \
  --data-file=demo/keys/2._watermark-text.demo.terryzink.com.private.pem
```

To rotate later: `gcloud secrets versions add demo-wm-key --data-file=<pem>`.

The Cloud Run service account needs read access to each secret:

```bash
SA="$(gcloud iam service-accounts list --filter='displayName:Compute' --format='value(email)')"
for s in demo-wm-key demo-wm-key-2; do
  gcloud secrets add-iam-policy-binding $s \
    --member="serviceAccount:$SA" --role=roles/secretmanager.secretAccessor
done
```

## 2. Deploy

Run from the **repo root** (the directory with the `Dockerfile`):

```bash
gcloud run deploy xboundary-demo \
  --source . \
  --region us-central1 \
  --allow-unauthenticated \
  --max-instances 1 \
  --min-instances 0 \
  --memory 512Mi --cpu 1 \
  --set-env-vars DEMO_KEY_LOCATOR=1._watermark-text.demo.terryzink.com,DEMO_KEY_LOCATOR_2=2._watermark-text.demo.terryzink.com \
  --set-secrets DEMO_PRIVATE_KEY_PEM=demo-wm-key:latest,DEMO_PRIVATE_KEY_PEM_2=demo-wm-key-2:latest
```

- First run offers to create an Artifact Registry repo (`cloud-run-source-deploy`)
  -- say yes.
- `--max-instances 1` keeps the in-memory rate limiter coherent and caps cost.
- The server reads `PORT` (Cloud Run sets it) and binds `0.0.0.0` via `HOST`
  (set in the Dockerfile). Each `DEMO_PRIVATE_KEY_PEM[_N]` + `DEMO_KEY_LOCATOR[_N]`
  pair (N up to 5) is turned into `keys/<locator>.private.pem` at startup; keys
  are never in the image.
- The watermark tab's algorithm for each key is read from that key's DNS `a=`
  tag (cached per instance -- a `a=` change needs a redeploy/restart to show).

You get a `https://xboundary-demo-XXXX.run.app` URL. Test all four tabs there
first.

## 3. (optional) Map your subdomain

```bash
gcloud beta run domain-mappings create \
  --service xboundary-demo \
  --domain demo.terryzink.com \
  --region us-central1
```

It prints DNS records (a `CNAME` to `ghs.googlehosted.com`, or `A`/`AAAA`).
Add them at your DNS host. Google provisions the TLS cert automatically once
the records resolve (a few minutes to a few hours). You must have verified
`terryzink.com` in Google Search Console under the same account.

## Updating

Re-run the `gcloud run deploy` command from step 2. Each deploy builds a fresh
image and shifts traffic when it's healthy.

## Notes

- **Cost:** effectively $0. Free tier is 2M requests + 360k GB-s + 180k vCPU-s
  per month; a demo won't approach it, and idle costs nothing at
  `--min-instances 0`.
- **Cold start:** ~2-4s for the first request after idle.
- **SSRF:** `safe_fetch` already refuses link-local (`169.254.0.0/16`), so the
  Cloud Run metadata server is not reachable from the `d=` fetcher. The HTTPS +
  public-IP checks re-run on every redirect hop.
- **DNS:** `dig` uses UDP/53 outbound, which Cloud Run allows. If it ever fails,
  switch the `dig` calls in `tools/watermark_dns_tool.py` to `dig +tcp`.
