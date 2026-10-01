# WhatsApp BillMate Assistant

## Guided chat menu

Send `menu`, `hi` or `help`, then choose 1–10: Demand Search, own stock,
supplier comparison, supplier orders, invoice/PDF, customer receivables,
supplier payables, reports, invoice preparation, purchase preparation.
An item list sent from the main menu still performs Demand Search directly.
Supplier inventory imports are reserved for a separate future agent.

Receivables/payables display paginated numbered names; choose a name to see
its balance, invoices/purchases, payments and statement. `next`, `previous`
and a name search navigate the list. Numbers continue across pages (1–15,
16–30, 31–45) and can be entered directly from any page. Search results retain
the full list's numbers. The database keeps permanent per-account customer
and supplier numbers across conversations/restarts. New accounts append;
renaming, deactivation or deletion does not reassign an existing number.
An account code such as `CUST-0017` also selects the named account directly.
`back` returns to the previous step,
`menu` returns home and `cancel` discards the current task. Conversations
persist in the database across runner restarts and expire after 24 hours.

Orders/drafts require explicit unit quantities and one selected offer per
demand item. Review candidates require the user's verification. Supplier
orders/purchases use supplier discounts, never a customer's billing discount;
missing supplier terms prevent generation. Orders are returned to the agent's
creator to forward; this integration never contacts suppliers directly.

Saving a preparation requires the preview's unique `confirm CODE` within
30 minutes. Saved preparations open in the existing Billing/Purchase editors.
They do not change stock, payments or balances, or post invoices. The user
reviews and saves the actual bill in the editor. These preparation records
are separate from invoices/purchases and aren't included in business backups.
Owner permissions are rechecked on each step and when a draft is opened.
Invoice PDFs reuse BillMate's existing server renderer.

The private runner credential now grants access to the account's permitted
assistant features, including financial records and confirmed preparations.
Keep it private; revoke it by regenerating the configuration or removing
the agent connection. It cannot import inventory, post bills or make payments.

## Run on your office laptop

Install Node.js 22 or newer. Save `stored-key-runner.cjs` and a private `.env`
file containing the two generated `BILLMATE_POLL_*` settings in one folder.
From that folder, run `node --env-file=.env stored-key-runner.cjs`.
No npm packages, BillMate password or WhatsApp key are needed for this runner.
Keep the laptop awake and connected, and leave the terminal running. You can
then chat from your phone away from the office; BillMate's browser need not
remain open. Stop the trial listener once the laptop runner is active. Restart
the runner after a laptop restart. A sleeping, shut-down or offline laptop
cannot process messages. Hosting is not provisioned automatically.

## Save the key in BillMate

Open **Admin → WhatsApp Agent**, paste the key into the password field and press
**Save & Verify Key**. BillMate verifies it with WhatsApp, encrypts it using the
stable server `SECRET_KEY`, and stores it for the signed-in account. No account
password is needed for this mode, and no plaintext agent key is returned by the
setup/status APIs or included in data backups.

For a live trial, click **Start Trial Listener** and keep the page open while
you send a demand in WhatsApp. The page checks for messages every six seconds.
Suspending the page on mobile can suspend processing. The listener is a trial,
not an always-on hosting service.

For background replies, generate a private runner configuration on that page,
set `BILLMATE_POLL_URL` and `BILLMATE_POLL_TOKEN` on a persistent Node 22+ host,
and run `node stored-key-runner.cjs` (or `npm run start:stored` with `.env`).
This runner holds a revocable Assistant polling credential; the
WhatsApp key and processing stay server-side in BillMate. Rotate its token or
remove the connection in BillMate to revoke access. The host must be provided
separately; saving the key does not provision it.

The Flask server uses QuickJS to run the same matching and text parsing modules
as the web page. Poll offsets, recent handled message IDs and a database lease
are saved per account. Failed processing/replies leave the offset unchanged.
Crashing after a successful delivery but before recording it can still repeat
a reply; business records remain unchanged. A failed delivery rolls back the
conversation step and any preparation save so retrying cannot leave a hidden
saved draft.

The connection table is created on first use. `SECRET_KEY` must remain stable;
changing it requires saving the WhatsApp key again. Stop the trial listener
before rotating or removing a key. A database lease prevents overlapping
listeners from processing one connection simultaneously.

Route tests: `python -m unittest discover -s tests -p test_whatsapp_agent.py`.

## Original direct worker

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
