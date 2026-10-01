# WhatsApp Demand Search pilot

Uses the consumer WhatsApp **Settings → Agents** feature, not WhatsApp Business.
Send a demand document or paste a demand list; the worker searches inventory
already visible to the configured BillMate account using the existing web matcher.
It reports demand quantities, item names, TP, discount and vendor, marking uncertain
offers as REVIEW. Long results are returned as a TXT attachment.

No supplier import, purchases, invoices or stock writes are implemented.

## Run a private trial

1. In normal WhatsApp, create an agent named **BillMate Demand**. Open its chat
   info and obtain the API key. The feature must be enabled for your account.
2. On a trusted computer or persistent Node 22+ worker host, run `npm ci` here.
3. Copy `.env.example` to `.env` and set the agent key and BillMate account login
   privately. Do not send secrets in WhatsApp or commit them. Restrict `.env`
   permissions to its owner (`chmod 600 .env`).
4. Run `npm test`, then `npm start`. Run exactly one worker per agent key and keep
   its `state.json` on a persistent disk so restarts retain the polling offset.
5. Send `help`, then a short pasted demand or TXT file. Verify the vendor offers
   against BillMate's Demand Search before trying larger files.
6. Test a PDF and your actual HTM demand attachment. PDF extraction uses the
   existing authenticated BillMate endpoint. Image-only PDFs remain unsupported.

The first poll reads the retained backlog (`offset=0`); use a newly created agent
for this trial. Processed message IDs and the offset are persisted, not files or
result contents. A crash between sending a reply and saving state can repeat a
read-only search or reply. There are no automatic retries of message sends.

The worker requires a persistent process. A short-lived Vercel request function
does not provide the continuous polling used here. Keep the worker running for
the trial; stopping it pauses replies. Never run this from a public shared host.
The private configuration currently stores the account password in environment
variables; a production deployment should use a dedicated scoped BillMate token.

## Attachment limits

The official Agent Platform manual v1 supports inbound document download,
PDF/TXT and a generic binary MIME type, with 16 MB document/binary limits.
This pilot follows BillMate's smaller limits: PDF 8 MB; TXT/HTML 4 MB.
HTML parsing is implemented, but **delivery of HTM/HTML through the WhatsApp
client must be verified live** because these extensions are not explicitly listed
in the manual. ZIP and Excel parsing are outside this pilot.

Official reference:
https://www.whatsapp.com/developer/WhatsApp-Agent-Platform-Developer-Manual.pdf

## Verification

`npm test` covers shared matching, vendor results, authorization filtering,
read-only inventory access, safe attachment download, file size limits,
inbound envelopes and non-executing HTML parsing. No live WhatsApp or BillMate
account has been used by these tests.
