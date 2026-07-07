import crypto from "crypto";

export interface Lead {
  email: string;
  phone?: string;
  source: string;
  firstName?: string;
  /** Extra Mailchimp tags beyond the source (e.g. "prospective-investor"). */
  tags?: string[];
}

/**
 * Routes a captured lead into a CRM. Two independent, optional channels:
 *
 *   1. Mailchimp (direct) — set MAILCHIMP_API_KEY + MAILCHIMP_AUDIENCE_ID.
 *      The datacenter prefix (e.g. "us21") is read from the key suffix, or
 *      from MAILCHIMP_SERVER_PREFIX if the key has none.
 *   2. Generic webhook — set LEAD_WEBHOOK_URL (e.g. a Zapier "Catch Hook"),
 *      which can then fan the lead out to Mailchimp or any other CRM.
 *
 * Both are best-effort and never throw: a CRM outage must not stop a visitor
 * from unlocking content or block the local DB write. Failures are logged.
 */
export async function routeLeadToCrm(lead: Lead): Promise<void> {
  await Promise.allSettled([syncToMailchimp(lead), postToWebhook(lead)]);
}

async function syncToMailchimp(lead: Lead): Promise<void> {
  const apiKey = process.env.MAILCHIMP_API_KEY;
  const audienceId = process.env.MAILCHIMP_AUDIENCE_ID;
  if (!apiKey || !audienceId) return; // not configured — skip silently

  const dc = apiKey.includes("-")
    ? apiKey.split("-")[1]
    : process.env.MAILCHIMP_SERVER_PREFIX;
  if (!dc) {
    console.error("[crm] MAILCHIMP_API_KEY missing datacenter suffix and MAILCHIMP_SERVER_PREFIX unset");
    return;
  }

  const email = lead.email.toLowerCase().trim();
  const subscriberHash = crypto.createHash("md5").update(email).digest("hex");
  const base = `https://${dc}.api.mailchimp.com/3.0/lists/${audienceId}/members/${subscriberHash}`;
  const auth = `Basic ${Buffer.from(`any:${apiKey}`).toString("base64")}`;

  const mergeFields: Record<string, string> = {};
  if (lead.phone) mergeFields.PHONE = lead.phone;
  if (lead.firstName) mergeFields.FNAME = lead.firstName;

  const allTags = [lead.source, ...(lead.tags ?? [])];

  try {
    // 1) PUT upserts the member (create or update) by subscriber hash.
    const res = await fetch(base, {
      method: "PUT",
      headers: { Authorization: auth, "Content-Type": "application/json" },
      body: JSON.stringify({
        email_address: email,
        status_if_new: "subscribed",
        merge_fields: mergeFields,
      }),
    });
    if (!res.ok) {
      const detail = await res.text();
      console.error(`[crm] Mailchimp upsert failed (${res.status}): ${detail}`);
      return;
    }

    // 2) Apply tags via the tags endpoint — this works for BOTH new and
    //    existing members (tags in the PUT body only apply on create).
    const tagRes = await fetch(`${base}/tags`, {
      method: "POST",
      headers: { Authorization: auth, "Content-Type": "application/json" },
      body: JSON.stringify({
        tags: allTags.map((name) => ({ name, status: "active" })),
      }),
    });
    if (!tagRes.ok) {
      console.error(`[crm] Mailchimp tagging failed (${tagRes.status})`);
    }
  } catch (err) {
    console.error("[crm] Mailchimp sync error:", err);
  }
}

async function postToWebhook(lead: Lead): Promise<void> {
  const webhookUrl = process.env.LEAD_WEBHOOK_URL;
  if (!webhookUrl) return; // not configured — skip silently

  try {
    const res = await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...lead, capturedAt: new Date().toISOString() }),
    });
    if (!res.ok) {
      console.error(`[crm] Webhook post failed (${res.status})`);
    }
  } catch (err) {
    console.error("[crm] Webhook post error:", err);
  }
}
