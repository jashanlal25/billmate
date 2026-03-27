---
title: BillMate Backend
emoji: ⚡
colorFrom: indigo
colorTo: purple
sdk: docker
app_port: 7860
pinned: false
---

# BillMate — Billing System Backend

Flask backend with PostgreSQL (Aiven). Serves the full billing system including templates and static files.

## Environment Variables (set as Secrets in HF Space settings)

| Variable | Description |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string (Aiven) |
| `SECRET_KEY` | Flask session secret key |
