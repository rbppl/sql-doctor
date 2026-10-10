# First-user launch checklist

**Status: not yet ready for a public launch.** The source-code checks are passing, but legal operator details, production billing, offsite backup, and real browser/production checks remain.

## 1. Operator and legal pages — launch blocker

- [ ] Replace every bracketed field in `frontend/imprint.html` with the real legal operator name, serviceable address, contact details and any applicable company/register/VAT information.
- [ ] Replace all bracketed fields in `frontend/privacy.html`: controller contact, lawful bases, exact processor list, data transfers, log/support retention and backup retention.
- [ ] Complete `frontend/terms.html`: legal provider, Pro price/currency/tax treatment, renewal/cancellation terms, applicable consumer withdrawal information and reviewed liability terms.
- [ ] Have the imprint, privacy notice, terms, and consumer checkout wording reviewed for the operator's actual country and business model. The current pages are templates, not legal advice.
- [ ] Update the contact route/address if the legal contact email changes.
- [ ] Remove `noindex` from legal pages only after all placeholders have been completed and reviewed.

## 2. Stripe — required before charging users

- [ ] Create the actual recurring Pro Price in Stripe; decide and document the amount, currency, tax treatment, billing interval, trial (if any), cancellation policy and refund process.
- [ ] Configure Render secrets `STRIPE_SECRET_KEY`, `STRIPE_PRICE_ID`, `STRIPE_WEBHOOK_SECRET`.
- [ ] Register `https://developer-doctor-backend.onrender.com/api/billing/webhook` in Stripe and subscribe to `checkout.session.completed`, `customer.subscription.created`, `customer.subscription.updated`, `customer.subscription.deleted`, and `invoice.payment_failed`.
- [ ] Test with Stripe test-mode keys first: successful checkout, cancellation, failed payment, subscription renewal/cancellation, portal, duplicate webhook delivery, and invalid signatures.
- [ ] Confirm the displayed price and legal terms match the exact Stripe Price. Do not enable live payments before this is done.

## 3. Database, encryption and backups

- [ ] Configure `GITHUB_TOKEN_ENCRYPTION_KEY` as a stable, random secret in Render and store a secure backup of the key outside the application. The latest startup code migrates legacy tokens when configured.
- [ ] Configure GitHub Actions secrets `BACKUP_DATABASE_URL`, `BACKUP_S3_URI`, `BACKUP_AWS_ACCESS_KEY_ID`, `BACKUP_AWS_SECRET_ACCESS_KEY`, and `BACKUP_AWS_REGION`. Use an external Render PostgreSQL URL for GitHub-hosted runners and least-privilege S3 credentials.
- [ ] Configure private bucket access and a lifecycle/retention policy; document the actual retention period in the privacy notice.
- [ ] Manually run `Scheduled database backup`; confirm the uploaded dump and its `sha256` object metadata.
- [ ] Create a **separate, empty PostgreSQL database** for restore testing and configure the repository secret `RESTORE_DATABASE_URL` to point only to that database (never production).
- [ ] Run `Database backup restore drill` from GitHub Actions with the exact S3 object URI; confirm checksum verification, archive readability, restore completion and core schema checks.
- [ ] Resolve the Render PostgreSQL free-tier expiry before **2026-11-04**. Test migration, rollback/restore and service connectivity before deleting or replacing the old database.

## 4. Production smoke tests

- [ ] Confirm latest backend and frontend Render deployments are `live` on the same intended commit.
- [ ] Open `/health` and verify HTTP 200, `database: true`, and reasonable database latency.
- [ ] Complete GitHub OAuth in a real browser, including the cross-origin session cookie; test logout and login again.
- [ ] Test repository scan, PR scan, scan history, JSON report export, daily quota enforcement and error states.
- [ ] Test account deletion on a disposable test account; confirm local history is removed and GitHub authorization is revoked or can be revoked manually.
- [ ] Confirm `/metrics` is not public and requires `MONITORING_BEARER_TOKEN`; configure external uptime monitoring and an alert recipient.
- [ ] Verify mobile layout, keyboard focus, accessible button labels, legal footer links and all legal-page placeholders.
- [ ] Test the free plan with real first-user accounts before inviting paying customers.

## 5. First-user rollout

- [ ] Start with a small invite-only group; label findings as heuristic and collect feedback.
- [ ] Publish a support/contact channel and a short incident-response procedure.
- [ ] Review logs for errors and false positives daily during the first week; never log tokens, repository file contents, or secrets.
- [ ] Confirm backup and restore are operational before onboarding users who depend on scan history.
- [ ] Do not describe the product as a security scanner or guarantee code correctness; it performs static heuristic checks.
