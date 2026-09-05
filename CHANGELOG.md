# Changelog

## v2.0 — Full spec rebuild

- Added Temporal and Environmental metric groups (previously Base-only).
- Fixed Scope-dependent Privileges Required weighting, which the original
  Base-only version did not account for.
- Added CVSS vector string generation and parsing (paste-to-load).
- Added shareable links (vector encoded as a URL query parameter).
- Rebuilt the UI: live-updating severity gauge, tabbed metric groups, chip-based
  metric selection instead of dropdowns, light/dark theme with persistence.
- Extended the PDF report to include all three scores and every selected metric.
- Split the single HTML file into `index.html` / `style.css` / `script.js`.

## v1.0 — Original course project

- Base Score calculator built for the VARE (Vulnerability Assessment & Risk
  Evaluation) course, Semester 7.
- Single-file HTML/CSS/JS with dark mode toggle and a basic PDF report.
