<div align="center">

# 🛡️ CVSS 3.1 Calculator

**A live, spec-accurate scorer for the Common Vulnerability Scoring System v3.1**

Base · Temporal · Environmental — vector strings, shareable links, and PDF reports, all in the browser.

[![License: MIT](https://img.shields.io/badge/License-MIT-2fae63?style=for-the-badge)](LICENSE)
[![CVSS](https://img.shields.io/badge/CVSS-3.1-4fb3e0?style=for-the-badge)](https://www.first.org/cvss/v3.1/specification-document)
![HTML5](https://img.shields.io/badge/HTML5-e2792f?style=for-the-badge&logo=html5&logoColor=white)
![CSS3](https://img.shields.io/badge/CSS3-1478a8?style=for-the-badge&logo=css3&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-d9a52c?style=for-the-badge&logo=javascript&logoColor=black)

</div>

>  Developed as a **Semester 7 course project for VARE (Vulnerability Assessment & Reverse Engineering).**

---

## 📋 Table of contents

- [Features](#-features)
- [Preview](#-preview)
- [Usage](#-usage)
- [Project structure](#-project-structure)
- [Scoring reference](#-scoring-reference)
- [License](#-license)
- [Author](#-author)

## ✨ Features

| | |
|---|---|
| 🧮 **Full metric coverage** | Base, Temporal, and Environmental groups, each with a live sub-score |
| ✅ **Spec-verified scoring** | Implements the official `Roundup()` function and the Scope-dependent Privileges Required weighting — a common source of bugs in hand-rolled calculators — checked against the reference vectors in the [FIRST.org specification](https://www.first.org/cvss/v3.1/specification-document) |
| 🔤 **Vector string in, vector string out** | Generates a standard `CVSS:3.1/...` vector as you score, and parses one back in — paste a vector straight from an NVD entry, an advisory, or a scanner report |
| 🔗 **Shareable links** | "Copy share link" encodes the current vector into a URL, so a scored vulnerability reopens pre-filled for a teammate |
| 📄 **PDF report export** | A formatted report with the vector string, all three scores, every selected metric, and standard mitigation guidance, via [jsPDF](https://github.com/parallax/jsPDF) |
| 🌗 **Light / dark theme** | Persisted across visits, defaulting to the visitor's OS preference |
| ⌨️ **Keyboard-accessible** | `aria-pressed` toggle chips and visible focus states throughout |

## 🖼️ Preview
<div align="center">
<img width="1731" height="1536" alt="Screenshot_5-9-2026_123031_" src="https://github.com/user-attachments/assets/5c41a15d-440b-42ff-afcc-0e3947ecd94a" />
</div>

<div align="center">
<sub>CVSS 3.1 Vulnerability Scoring Calculator.</sub>
</div>

## 🚀 Usage

Open `index.html` directly in a browser, or serve the folder with any static file server:

```bash
npx serve .
# or
python3 -m http.server
```

Pick metric values as chips — each one shows its CVSS weight — and the score, gauge, and vector string update live. Switch tabs to layer on Temporal and Environmental metrics; anything left as "Not Defined" is excluded from the vector string, per spec.

## 📁 Project structure

```
├── index.html      # markup
├── style.css       # design tokens + layout
├── script.js       # scoring engine, vector parser, UI, PDF export
└── README.md
```

## 🧠 Scoring reference

All formulas follow the FIRST.org CVSS v3.1 Specification Document, Sections 6–8:

| Score | How it's derived |
|---|---|
| 🟢 **Base** | Exploitability and Impact sub-scores over Attack Vector, Attack Complexity, Privileges Required, User Interaction, Scope, and the Confidentiality / Integrity / Availability triad |
| 🟡 **Temporal** | Base Score scaled by Exploit Code Maturity, Remediation Level, and Report Confidence |
| 🟠 **Environmental** | A re-derivation of Impact and Exploitability using Modified Base metrics and CIA Requirements, then scaled by the Temporal multipliers |

## 📜 License

MIT — see [LICENSE](LICENSE).

## 👤 Author

**Muhammad Zohaib**

[![GitHub](https://img.shields.io/badge/GitHub-zohaibjaved--zj-171515?style=flat-square&logo=github&logoColor=white)](https://github.com/zohaibjaved-zj)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Muhammad_Zohaib-1478a8?style=flat-square&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/muhammad-zohaib-46436a282)
