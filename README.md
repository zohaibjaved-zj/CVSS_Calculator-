# CVSS 3.1 Calculator

A browser-based calculator for the [Common Vulnerability Scoring System v3.1](https://www.first.org/cvss/v3.1/specification-document) — Base, Temporal, and Environmental scores, vector string import/export, shareable links, and PDF reporting. No backend, no build step: open `index.html` or serve it as a static site.

> Originally built as a course project for **VARE (Vulnerability Assessment & Risk Evaluation)**, Semester 7, and rebuilt into a fuller implementation of the spec.

## Features

- **Full CVSS 3.1 metric groups** — Base, Temporal, and Environmental, each with live sub-scores.
- **Correct, spec-verified scoring** — implements the official `Roundup()` function and the Scope-dependent Privileges Required weighting (a common source of bugs in hand-rolled calculators), checked against the reference vectors published in the [FIRST.org specification](https://www.first.org/cvss/v3.1/specification-document).
- **Vector string in, vector string out** — the tool generates a standard `CVSS:3.1/...` vector as you score, and can parse one back in (paste a vector from an NVD entry, an advisory, or a scanner report).
- **Shareable links** — "Copy share link" encodes the current vector into a URL query parameter so a scored vulnerability can be sent to a teammate and reopen pre-filled.
- **PDF report export** — a formatted report with the vector string, all three scores, every selected metric, and standard mitigation guidance, via [jsPDF](https://github.com/parallax/jsPDF).
- **Light/dark theme**, persisted across visits, defaulting to the visitor's OS preference.
- **Keyboard-accessible** metric controls (`aria-pressed` toggle chips) and visible focus states.

## Usage

Open `index.html` in a browser, or serve the folder with any static file server:

```bash
npx serve .
# or
python3 -m http.server
```

Pick metric values as chips (each shows its CVSS weight); the score, gauge, and vector string update live. Switch tabs to layer on Temporal and Environmental metrics — anything left as "Not Defined" is excluded from the vector string, per spec.

## Project structure

```
├── index.html      # markup
├── style.css       # design tokens + layout
├── script.js       # scoring engine, vector parser, UI, PDF export
└── README.md
```

## Scoring reference

All formulas follow the FIRST.org CVSS v3.1 Specification Document, Sections 6–8:

- **Base Score** — from Exploitability and Impact sub-scores over Attack Vector, Attack Complexity, Privileges Required, User Interaction, Scope, and the Confidentiality/Integrity/Availability triad.
- **Temporal Score** — Base Score scaled by Exploit Code Maturity, Remediation Level, and Report Confidence.
- **Environmental Score** — a re-derivation of Impact and Exploitability using Modified Base metrics and Confidentiality/Integrity/Availability Requirements, then scaled by the Temporal multipliers.

## License

MIT — see [LICENSE](LICENSE).

## Author

Muhammad Zohaib ([GitHub](https://github.com/zohaibjaved-zj) · [LinkedIn](https://www.linkedin.com/in/muhammad-zohaib-46436a282))
