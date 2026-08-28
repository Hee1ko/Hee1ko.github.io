# hee1ko.com

My personal site: resume, work history, and write-ups of things I have built.

Hand-written HTML and CSS. No framework, no build step, no dependencies, no
tracking. `git push` publishes it via GitHub Pages.

## Why no build step

There are about ten static pages here. A framework would add a build that can
fail between a commit and the live site, plus a Node version that rots, in
exchange for saving a duplicated fifteen-line header. The engineering worth
looking at in this repo is `tools/scrub.py` and the deck layout probe, not a
bundler config.

If the page count passes ~20 this becomes the wrong call, and the fix is Astro
or Eleventy behind a GitHub Action. Not before.

## Local preview

```sh
tools/serve.sh          # http://127.0.0.1:8000
```

Two ways this differs from GitHub Pages, so you don't chase phantoms:

- `http.server` serves its own 404, not this repo's `404.html`.
- `http.server` does not redirect `/resume` to `/resume/`. Pages does. Test with
  the trailing slash.

## The confidentiality gate

I work on customer support cases. Nothing from that work can appear here — no
customer names, no case detail, no internal system names, no account IDs. Good
intentions are not a control, so this is enforced mechanically.

```sh
tools/install-hooks.sh              # run once per clone
python3 tools/scrub.py --self-test  # prove the gate still catches violations
python3 tools/scrub.py --all        # scan every tracked file
python3 tools/scrub.py --history     # scan every blob in every commit
```

`tools/scrub.py` blocks commits containing internal hostnames, internal system
names, 12-digit account IDs, 17-digit case IDs, credential shapes, my phone
number, unlicensed font names, and a private list of confidential terms. It runs
as a `pre-commit` hook, again on `pre-push` across the full history, and again in
CI where `--no-verify` cannot reach it.

Three design decisions in there that took a second attempt to get right:

1. **Staged content is read from the git index, not the working tree.** Reading
   the worktree lets you stage a bad version, fix the file locally, and commit
   the bad blob straight past the gate.
2. **PDFs are extracted with `pdftotext` before scanning.** PDF text is
   Flate-compressed, so a plain grep sees nothing. The gate fails closed if it
   cannot read a PDF. The resume PDF is generated from the already-scrubbed HTML
   for the same reason — never copied from a private source.
3. **The list of confidential terms is not in this repo.** A public repo
   containing a readable list of customer names would be the exact leak the gate
   exists to prevent. Only salted hashes are committed
   (`tools/banned-hashes.txt`); the plaintext lives outside the repo and
   `tools/make-hashes.py` regenerates the hashes from it. Hashing company names
   is obfuscation, not encryption — a determined reader with a company list could
   confirm a guess. It defends against accidental disclosure and casual reading,
   which is the actual threat. The real protection is that those names never get
   written into this repo at all.

The self-test is not optional. A gate that has silently stopped matching is worse
than no gate, because it manufactures confidence — so CI runs the self-test
before it trusts the gate's verdict.

## Structure

```
index.html            home
about/                the long version of a non-linear path
work/                 project index
work/<slug>/          one page per project
work/<slug>/deck/     clickable slide deck: thin page + shared engine + slides.js
resume/               GENERATED -- see below
assets/css/           tokens.css (design tokens), site.css, resume.css
assets/deck/          shared slide engine
tools/                the scrub gate, hooks installer, local server
```

`resume/index.html` and `resume/heewon-ko-resume.pdf` are **generated**. The
source of record is a private repo; a script there scrubs it and writes the
output here. Editing them by hand gets overwritten. There is deliberately no
symlink or submodule between the two repos — a submodule would publish the
private repo's URL and commit SHAs, and a symlink either serves a 30-byte link
file or drags the private content into this tree.

## Design system

`assets/css/tokens.css` is the single source of truth: four greys, exactly one
accent, one type scale. Every other stylesheet uses those tokens and no literal
colours.

Contrast ratios are measured, not estimated. Two colours inherited from an
earlier version of my resume were replaced because they fail WCAG AA for body
text on this paper colour:

| was       | ratio  | now              | ratio  |
| --------- | ------ | ---------------- | ------ |
| `#c15f3c` | 4.01:1 | `#b85536` accent | 4.54:1 |
| `#7d7a70` | 4.08:1 | `#736c64` meta   | 4.91:1 |

Type is the system font stack, deliberately: zero bytes, zero licensing
question. A webfont goes behind `--font-display` if and when one is worth it —
and only after reading its licence, because redistributing font files in a public
repo is a stricter test than "free for commercial use".

## Licence

`MIT` covers `assets/` and `tools/`. Take the scrub gate if it is useful to you.
The written content, the resume, and the photographs are not licensed for reuse.
