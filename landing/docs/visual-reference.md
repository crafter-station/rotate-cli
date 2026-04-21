---
project: rotate-cli
slug: hunt-rotate-cli
date: 2026-04-21
sourceImage: reference-desktop.png
style: manuscript-security
---

# Visual Reference — rotate-cli

## 1. Core Aesthetic

**Style name**: *Manuscript Security* — a cryptographic-feeling hybrid of Renaissance strategy notebook + modern security tool.

**One-sentence design philosophy**: Secrets rotation is ancient craft dressed in new tech — the interface should read like a cryptographer's lab journal, not a SaaS dashboard.

**Key influences / hybrid styles**:
- Chess strategy manuscripts (Da Vinci's codices, Fischer's endgame notebooks)
- Vercel/Linear dense-information density meets Tufte-style analog layering
- Monospace-meets-handwritten tension (terminal code over parchment)
- Strategic warfare mood — single black king commanding a scattered battlefield of papers

Unlike standard security tool design (cold blues, neon terminals, glassmorphism), this aesthetic lands on *intellectual authority*: weathered paper, ink-stain textures, muted gold/bronze, one dominant dark chess piece as focal point. It says "this is the tool of someone who *thinks* about secrets, not just ships them."

## 2. Color Palette

| Name | Hex | Usage |
|---|---|---|
| Parchment Ivory | `#E8E1D3` | Primary background (paper texture base) |
| Parchment Cream | `#D8D0BE` | Secondary background, layered documents |
| Parchment Shadow | `#A39B89` | Tertiary background, creased paper depth |
| Ink Black | `#1A1612` | Primary text, king piece, bold strokes |
| Graphite Dark | `#3A332B` | Secondary text, body copy |
| Graphite Mid | `#6B6253` | Muted text, metadata, timestamps |
| Bronze | `#8A6E3B` | Accent primary — links, keywords, annotations |
| Antique Gold | `#B8954E` | Accent secondary — hover states, highlights |
| Sepia Ink | `#4A3A28` | Tertiary accent, quote marks, emphasis |
| Stone White | `#F2EEE4` | Card surfaces, code block backgrounds |
| Ember Rust | `#6E3A28` | Reserved — CRITICAL status, error states only |

**Group**:
- **Background layer**: Parchment Ivory / Cream / Shadow (gradient of aged paper)
- **Text layer**: Ink Black → Graphite Dark → Graphite Mid (tri-tone depth)
- **Accent layer**: Bronze + Antique Gold + Sepia Ink (never saturated, always muted)

## 3. Typography System

### Font families

| Role | Font | Fallback | Why |
|---|---|---|---|
| Display / hero | **EB Garamond** (variable) | Playfair, Georgia, serif | Renaissance manuscript feel, high contrast, scholarly |
| Body / UI | **Instrument Sans** | Inter, system-ui | Modern geometric-humanist, clean counterweight to Garamond |
| Mono / code | **JetBrains Mono** | IBM Plex Mono, monospace | Terminal-authentic, readable small, pairs well with Garamond |
| Hand / notes | **Caveat** (used sparingly) | Kalam, cursive | ONLY for single-line marginalia and chart annotations; never for body |

### Sizes

| Token | Size | Line height | Use |
|---|---|---|---|
| `hero` | 72px / 4.5rem | 1.05 | H1 hero title, single line |
| `h1` | 48px / 3rem | 1.1 | Section openers |
| `h2` | 32px / 2rem | 1.2 | Subsections |
| `h3` | 24px / 1.5rem | 1.3 | Card titles, adapter names |
| `body` | 17px / 1.0625rem | 1.6 | Paragraph copy (slightly larger than typical — matches manuscript readability) |
| `small` | 14px / 0.875rem | 1.5 | Metadata, labels |
| `micro` | 12px / 0.75rem | 1.4 | Timestamps, version numbers |
| `code` | 15px / 0.9375rem | 1.55 | Code blocks (slightly larger than body small for readability) |

### Weights + tracking

- **EB Garamond Display**: 500 (regular) or 600 (semibold) — never 700 (looks heavy on parchment)
- **Instrument Sans**: 400 body, 500 emphasis, 600 labels. Never 700.
- **JetBrains Mono**: 400 for code, 500 for inline `var_name`
- **Tracking**: `-0.02em` on display sizes (tighter, more authoritative), `0` on body, `+0.05em` on small/micro (breathing room on parchment)

### Stylistic choices

- **Ligatures ON** for Garamond (`st`, `ct`, `ffi` ligatures show the manuscript lineage)
- **Small caps** for labels and navigation — `font-variant: small-caps` on tags and adapter type labels
- **Italic Garamond** reserved for quotes and footnote-style asides
- **No uppercase transforms** — this design trusts its typography to carry hierarchy

## 4. Key Design Elements

### Textures & treatments

- `parchment-grain` — very subtle noise overlay (5-8% opacity) on all background sections. Can use a base64 SVG turbulence filter or a small tileable PNG.
- `edge-wear` — soft vignette on card edges, darker at corners, mimicking crumpled paper shadow. `box-shadow: inset 0 0 40px rgba(26, 22, 18, 0.08)`.
- `ink-bleed` — on hover, links gain a slightly smudged shadow (`text-shadow: 0.5px 0 0 currentColor`) to feel like ink on paper.
- `torn-edge` — section dividers use a subtle SVG mask with irregular edges instead of a clean 1px border.

### Graphic elements

- **Single dark silhouette focal point** — hero uses a subtle chess king silhouette offset to one side, low opacity (8-12%), never centered. The text is the king now, the piece just anchors the feeling.
- **Handwritten marginalia** — one Caveat-font annotation per section max, in Bronze, acting as pull-quote or footnote. Example: a small `// 17 adapters, zero servers` next to a code block.
- **Scattered card layout** — adapter cards on the landing are slightly rotated (`-1deg`, `+0.5deg`, `-0.3deg`) and overlapping like papers on a desk, NOT in a perfect grid.
- **Bronze underline for links** — subtle dotted/dashed underline in Bronze, reminiscent of quill emphasis.

### Layout structure

- **Asymmetric compositions** — no center-aligned hero. Content weighted to the left, accent element right (like the king in the reference image).
- **Baseline grid of 8px** but with irregular-feeling spacing via `clamp()` — nothing should look pixel-perfect algorithmic.
- **Density**: comfortable-to-dense. Manuscripts are packed with writing — don't be afraid of long paragraphs. Reader is a security practitioner, respects density.

### Unique stylistic choices

- `handwritten-annotation` — optional pseudo-element decorations using Caveat font for section subtitles ("a brief against manual rotation", "what we learned from Vercel").
- `quill-cursor` — on interactive CTAs, custom cursor with a small feather icon.
- `terminal-block-in-parchment` — code blocks are dark (Ink Black bg, Parchment Cream text) to contrast the warm parchment body, like ink on ink.
- `drop-cap-garamond` — first letter of long-form articles uses display-size Garamond in Bronze.

## 5. Visual Concept

**Conceptual bridge**: The chess king is the master secret. The scattered papers are the audit trail, the 1516 env vars, the rotation logs. The cracked table surface beneath is the legacy infrastructure that rotate-cli helps you organize. One piece, many pages — one CLI, many providers.

**Element relationships**:
- King piece (CLI) ↔ Scattered papers (adapters/audit) ↔ Parchment desk (infrastructure)
- Bronze highlights (accents) appear on interactive elements, as if marked in gold leaf
- Handwritten marginalia (Caveat) acts as "commentary from the author" — rare, intentional

**Ideal use cases**:
- Landing page hero with king silhouette as low-opacity background
- Adapter grid where each card feels like a catalogued manuscript page
- Code blocks styled as "terminal on parchment"
- Status badges (CRITICAL / HIGH / MEDIUM) as wax-seal-like circular emblems
- Documentation pages with drop caps and marginalia
- Never: loud gradients, glassmorphism, neon, aurora, 3D buttons, confetti

**What this aesthetic AVOIDS**:
- Blue/green "security SaaS" color palette (cold, generic)
- Glassy dark-mode terminal aesthetic (done to death)
- Cyberpunk neon (wrong mood — we're not playful, we're careful)
- Minimalist all-white SaaS (too cold, no personality)
- Linear-style bright dark theme (rotate-cli is not a dev tool, it's a *security* tool)
