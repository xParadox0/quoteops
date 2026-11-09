# QuoteOps: Product Requirements Document

Version 0.1, 7 November 2026. Status: for Yona's review. No code exists.
Owner: Yona Surya Pratama (Chronyx Labs). Sources: `RESEARCH-FINDINGS-AND-MVP.md`, `QUOTEOPS-DEPLOY-PLAN.md`, the 13-screen design "Chronyx QuoteOps", and measurements of VM110 taken on 7 November 2026.

## 1. Problem

A machining workshop in Indonesia prices custom parts from engineering drawings and writes invoices by hand. The owner's father runs such a shop. Two jobs are slow and error-prone: working out a price from a drawing, and producing the quotation and invoice from it.

Evidence behind the problem, and its limits:

| Evidence | What it shows | Limit |
|---|---|---|
| 1,182 app-store reviews of invoicing apps, 337 Hacker News items, 203 search suggestions, 16 vendor pages | Invoicing alone is already served: Kledo has a free plan, Jurnal starts at Rp399.000 a month, Invoice Ninja is free, ERPNext does quotations. Reviewers complain about price changes, bugs and forms that are too long. | Read from outside. No Indonesian workshop owner has been asked. |
| Five foreign vendors do drawing-to-quote (Paperless Parts, ProShop, Jump, Isonq, Jiga) | The cost-from-drawing half is where the gap is. | None found for Indonesian job shops. That is a gap in the search, not proof. |
| Willingness to pay | None. | Desk research cannot supply it. |

This document therefore describes a tool for one real shop first, built so that other shops can sign up. It does not claim a market.

## 2. Goals

| What is measured | Now | Target |
|---|---|---|
| Quotes where every value was confirmed by a person before the price was approved | Not measured (paper and spreadsheets) | 100 percent, enforced by the system |
| Time from a received drawing to a sent quotation | Not measured. To be timed in the shadowing session with the owner's father. | Set after that measurement |
| Shops able to sign up and finish a first quote without help from Chronyx | 0 | 3 pilot shops |
| One shop reading another shop's data | Not applicable | 0, proved by an automated two-company test on every release |
| Company data export and deletion on request | Not applicable | Both work and are tested |

## 3. Non-goals

- Reading values from drawings with a model. Version 1 has manual entry. The design leaves a place for it.
- Payments, billing, subscriptions, a marketplace, a mobile app.
- Tax advice. The tax rate and the invoice format are set by each company. The rules are checked against official sources before any feature relies on them.
- Real customer drawings until the owner's father says which may be used. Until then every shop and every sample is invented.
- Marketing email.

## 4. Users and moments

One product, four roles inside a company, plus the operator.

- Owner, at a desk in the afternoon: sets rates and margin, approves a price, sends the quotation.
- Estimator: reads a drawing, enters and confirms its values, fills the cost sheet.
- Accountant: turns an accepted quotation into an invoice and records payments.
- Viewer: reads jobs and documents.
- System administrator (Yona, Chronyx): manages the platform across all companies. Lists, suspends, reactivates and deletes companies and their users, resets a user's access, sets the caps, and sees usage numbers. Does not see drawings, prices or customer details. Looking inside a company needs that company's approval, with an end time, and is logged.
- Company Owner: signs up, gets their own company, and manages that company's users, roles and invites. Cannot see other companies or the platform pages.

## 5. Functional requirements

M = must for version 1, S = should, C = could.

| ID | Priority | Requirement |
|---|---|---|
| F1 | M | Anyone can sign up with email, company name and acceptance of the current terms. Sign-up creates one company and one Owner user. The account exists but cannot be used until the owner of the mailbox opens the verification link and chooses a password there (no password is asked at sign-up, so nobody can set the password of an address they do not control). |
| F2 | M | Sign-in with email and password, with a rate limit and lockout. Sign-out ends the session at once. |
| F3 | M | Password recovery. Needs a mail path (see open question Q1). |
| F4 | M | Email verification before a company may upload files or send documents. Verification happens when the owner of the mailbox opens the link, chooses the password, confirms the company name and accepts the terms. |
| F5 | M | Owner invites users by email link with a role. A link works once and expires in 7 days. |
| F6 | M | Roles Owner, Estimator, Accountant, Viewer with the permission table in the design. Only the Owner approves a price by default. |
| F7 | M | Every query is limited to the signed-in company. The limit lives in the database, not only in the application. |
| F8 | M | Create a job with customer, part, quantity, material, due date and one or more drawing files (PDF, DXF, PNG, JPG). |
| F9 | M | Value sheet: a list of values read from the drawing, each typed by a person, with source note and status (To confirm, Confirmed, Needs check, Not found). |
| F10 | M | Price approval is blocked until every value is Confirmed. The block is enforced on the server and the reason is shown. |
| F11 | M | Rates per company: machine hourly rates, setup, tooling percent, default margin. |
| F12 | M | Cost sheet from the rates and confirmed values, margin, price per piece and total, with every line traceable to its rate. |
| F13 | M | Past jobs of the same company shown as a labelled guide, never as a prediction. |
| F14 | M | Quotation and invoice as A4 PDF with the company's own number series, logo, tax setting and bank details. |
| F15 | M | Company profile and data and privacy page, export of all company data, deletion of the company and everything in it. |
| F16 | M | Privacy policy and terms, versioned. Acceptance is recorded with version and time. |
| F17 | M | Quotas per company and global caps (section 6). Over a cap the page says why and what to do. |
| F18 | M | System administrator pages: all companies and users, suspend, reactivate, delete, disable a user, caps, usage counts. Content stays hidden (see F7 and the support grant). Every action is logged. |
| F25 | M | The first administrator is created from the command line on the server. No sign-up path can create one. Admin sign-in uses the same password rules plus a second factor: a code from an authenticator app (Q5, decided). |
| F19 | S | Audit trail per job: who changed which value and when. |
| F20 | S | Light and dark theme from the design, chosen per user. |
| F21 | S | Indonesian language for the interface. English first. |
| F22 | C | Model-assisted reading of drawings. Every value it proposes stays To confirm. |
| F23 | C | Send quotation by email from the app. |
| F24 | C | Recurring customers and a customer list screen. |

## 6. Non-functional requirements

- Isolation: two companies cannot see each other's rows or files. Proved by a test with two companies on every release.
- Honest numbers: every money figure on a screen traces to rates and confirmed values. A script recomputes it in the tests.
- Failure is visible: a failed PDF, upload or mail shows an error with the cause and the next step. Nothing fails silently.
- Security: passwords hashed with scrypt, sessions in the database with expiry, cookies HttpOnly, Secure and SameSite, CSRF token on every form, uploads checked by content type and size, files served only to the signed-in company, never rendered by the server.
- Personal data: the product stores email, name and the company's own customer details. The operator is the data controller for that. Retention, export and deletion are written in the privacy policy before sign-up opens.
- Caps, defaults changeable by the operator: 20 companies in total, 5 users, 50 jobs a month, 25 MB per file and 500 MB per company. "20 companies" counts verified companies only: a sign-up counts once the owner of the mailbox has opened the verification link and chosen the password. Unverified sign-ups are deleted after 72 hours. Sign-ups limited per address and per hour.
- Size: runs on VM110 beside Saku. Measured on 7 November: 3.9 GB of 5.85 GB free, 64 GB of disk free, the Saku web container 24 MB, its database 8.9 MB. A web container and a database for QuoteOps fit. One heavy job at a time stays the rule on this machine.

## 7. Growth estimate

Worst case at the caps: 20 companies times 500 MB is 10 GB of uploads, against 64 GB free. Rows: 20 companies times 50 jobs a month times about 30 value and cost rows is 30,000 rows a month, which PostgreSQL handles without tuning. The first real limit is the 5.85 GB of memory shared with other services, not storage.

## 8. Risks

| Risk | Mitigation |
|---|---|
| One shop sees another's drawings or prices | Row-level security in PostgreSQL, a two-company test on every release, files stored under a company-random path and served only through an authorised route |
| Open sign-up invites abuse (bots, junk files) | Rate limits, email verification before uploads, caps, file type and size checks, bot challenge (Q2), operator can suspend a company |
| Sign-up works but nobody can recover a password | A mail path before sign-up opens (Q1) |
| Other people's business data on a personal server | Privacy policy and terms, consent record, export and delete, a legal check before the public opening (Q3) |
| The product repeats what ERPNext and Kledo already do | Version 1 centres on the value sheet and the cost sheet, which they do not. Invoicing is included because the shop needs it, not as the reason to exist. |
| No shop owner has said they would pay | The first shop is the owner's father. Interviews continue. Price stays unvalidated. |
| The machine is shared | Memory limits on the containers, backups before every change, nothing else stopped |
| Customers' drawings may be protected by the customer | The father decides which drawings enter the system. Until then only invented data. |

## 9. Decisions made and open questions

Decided by the owner on 7 November 2026:
- Build a real app, not a prototype. Run live at quoteops.chronyxlabs.com.
- Sign-up is self-service, without an approval step.
- Real drawings come later, from the owner.

Decided here, open to change:
- Stack and hosting as Saku (FastAPI, PostgreSQL 16, Docker, Cloudflare tunnel), with its own database.
- The sign-up form is built in stage 2 but the public opening is stage 6b, after the privacy policy, the terms and a legal check. Until then the site sits behind Cloudflare Access for the owner's two emails. This is a condition of opening sign-up to strangers, not a second approval step for users.

Open, each changes the build:
- Q1: decided: Microsoft Graph, sending as the shared mailbox quoteops@chronyxlabs.com through an Entra application fenced to that mailbox by an Exchange application access policy (HLD section 12). SPF is in place and DMARC is published with p=none (since 2026-11-09); the DKIM CNAMEs are published but signing starts only when Microsoft finishes provisioning the keys. Still open for the owner: tightening DKIM and DMARC for chronyxlabs.com, needed before mail goes to strangers.
- Q2: Bot protection. A Cloudflare Turnstile widget is the standard answer. The token on this server cannot create one (the API returned 403). The owner creates the widget in the Cloudflare dashboard, or extends the token. Without it, rate limits and email verification carry the load.
- Q3: Who reviews the privacy policy and the terms, and whether Indonesia's registration for private electronic system operators applies. I can draft. I cannot give legal advice.
- Q5: decided by the owner on 8 November 2026: the administrator's second factor is an authenticator-app code (TOTP), no mail needed. The admin sign-in may face the public internet, so it does not rely on Cloudflare Access (HLD section 11).
- Q4: The caps in section 6, and whether version 1 is free for everyone.
