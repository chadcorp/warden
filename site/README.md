# Warden landing site

A **zero-dependency static site** — plain HTML/CSS/JS, no framework, no build
step, no external fetches (system fonts only). It matches the project ethos:
nothing leaves the visitor's box, and it deploys anywhere.

```
site/
├── index.html      the landing page
├── styles.css      dark security-tooling aesthetic
├── app.js          terminal animation, scanner + rug-pull demos, waitlist form
├── favicon.svg     the shield mark
├── og-image.svg    social share card (1200×630)
└── README.md       this file
```

All copy mirrors the **real** reference output (trust badges, scanner findings,
the magic-moment terminal) — see [`../BUILD_REPORT.md`](../BUILD_REPORT.md).

## Run it locally

Any static server works. From the repo root:

```
py -m http.server 4173 --directory site
# open http://localhost:4173
```

## Before you deploy — two one-line edits

1. **Waitlist endpoint.** Open `app.js` and set `WAITLIST_ENDPOINT` to a URL that
   accepts a `POST {email}` — e.g. a free [Formspree](https://formspree.io)
   endpoint (`https://formspree.io/f/xxxx`), Buttondown, Netlify Forms, or your
   own. Left blank, the form runs in **preview mode**: it shows the success UX and
   logs a console warning, but does not send anything.
2. **Repo + URLs.** Replace `https://github.com/chadcorp/warden` (in `index.html`)
   with your real repository URL, and update the `og:image` / canonical URLs to
   your domain.

> **Social image note.** `og-image.svg` looks crisp and works on platforms that
> render SVG previews. Some (notably X/Twitter) only render raster `og:image`s —
> if you need guaranteed previews there, export `og-image.svg` to a 1200×630 PNG
> (open it in a browser and screenshot, or any SVG→PNG converter) and point the
> `og:image` / `twitter:image` meta tags at the PNG.

## Deploy

- **GitHub Pages** — set Pages to serve from this `site/` folder on a branch, or
  copy `site/`'s contents to a `gh-pages` branch root.
- **Netlify / Vercel / Cloudflare Pages** — point the project at `site/` as the
  publish directory; no build command needed.
- **Any host** — it's static files; upload them.

## Accessibility & performance

- Respects `prefers-reduced-motion` (terminal + reveals show instantly).
- Semantic landmarks, labeled form, keyboard-reachable controls.
- No render-blocking external requests; ships only what you see.
