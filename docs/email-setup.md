# Email transport (Resend)

Minister sends all outbound mail — sign-in magic links, the email-domain
plugin's verification link, and share-link emails — through a single
function, `apps/minister/src/lib/mailer.ts:sendMail`.

## Transport selection

| Environment | `RESEND_API_KEY` + `MAIL_FROM` set? | Behavior                                                    |
| ----------- | ----------------------------------- | ----------------------------------------------------------- |
| dev / test  | no                                  | prints the message to the server log (links stay clickable) |
| dev / test  | yes                                 | sends via Resend                                            |
| production  | no                                  | **throws** — never silently drops mail                      |
| production  | yes                                 | sends via Resend                                            |

`MAIL_FROM` must be an address on a domain **verified in the Resend
account**, e.g. `Minister <noreply@your-domain.com>`. An unverified
domain makes Resend return a 403 and `sendMail` throws with that detail.

## Verifying a live send (manual, one-time)

A live send was intentionally **not** run automatically — it needs a
human to confirm the sender domain and a safe recipient. To verify:

1. Put a send-capable Resend API key and a verified-domain sender in
   `apps/minister/.env` (gitignored):

   ```
   RESEND_API_KEY="re_..."
   MAIL_FROM="Minister <noreply@your-verified-domain>"
   ```

2. One-off probe with curl (replace the recipient with your own inbox):

   ```sh
   curl -s -X POST https://api.resend.com/emails \
     -H "Authorization: Bearer $RESEND_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"from":"Minister <noreply@your-verified-domain>",
          "to":["you@your-inbox"],
          "subject":"Minister test",
          "text":"It works."}'
   ```

   A `200` with an `{"id": "..."}` body means the sender domain is good.
   A `403` names the unverified domain.

3. End-to-end through the app: with the env set, restart the dev server,
   request a magic link, and confirm it lands in the inbox instead of
   the server log.

The Resend key found on the server (`resend-hwdynamics.env`) is
send-only (can't list domains via the API), so the verified sender
domain must be confirmed out of band — `freed.ink` is the likely
candidate given the FreedInk mail setup, but it wasn't confirmed.
