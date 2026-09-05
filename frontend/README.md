# Vantara Frontend

Next.js dashboard for the Vantara SOC platform — alert triage, MITRE ATT&CK
coverage, and detection metrics.

## Stack
Next.js 16 (App Router) · TypeScript · Tailwind CSS v4 · Radix UI primitives
(hand-built in the style of shadcn/ui — see Phase 7 setup notes on why the
shadcn CLI itself wasn't used) · TanStack Query · Recharts

## Local development (outside Docker)
```bash
npm install
cp .env.example .env.local
npm run dev
```
Requires the backend running separately (`docker compose up -d` from the
project root) — this app has no data of its own, it's a client for the
FastAPI backend's REST API.

## Building
```bash
npm run build
npm run lint
```

## Auth note
Tokens are stored in localStorage, not httpOnly cookies — see
`src/lib/auth.ts` for the explicit trade-off this makes and what a
hardened v2 would change.
