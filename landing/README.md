# rotate-cli — landing

Astro + Tailwind v4 landing for [rotate-cli](https://github.com/crafter-station/rotate-cli).
Deployed at https://rotate-cli.crafter.run.

## Stack

- Astro (static output, Vercel adapter)
- Tailwind CSS v4 (via `@tailwindcss/vite`)
- Vercel Analytics
- Design tokens in `docs/design-tokens.json` (see `docs/visual-reference.md`)

## Development

```bash
bun install
bun run dev
```

## Deploy

The repo is linked to Vercel — pushing to `main` triggers a deploy. Local
preview of the production build:

```bash
bun run build
bun run preview
```

## Design system

Manuscript Security aesthetic — weathered parchment background, single dark
chess piece as focal watermark, Garamond + Instrument Sans + JetBrains Mono,
muted bronze/gold accents. Every decision is documented in
`docs/visual-reference.md`.
