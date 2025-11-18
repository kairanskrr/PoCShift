# ✨ Learning from the Past: Real-World Exploit Migration for Smart Contract PoC Generation

[![ASE 2025](https://img.shields.io/badge/ASE-2025-blue?style=flat-square)](https://conf.researchr.org/home/ase-2025)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](https://opensource.org/licenses/Apache-2.0)
[![Paper PDF](https://img.shields.io/badge/Paper-PDF-orange?style=flat-square)](./full_paper/Learning%20from%20the%20Past%20Real-World%20Exploit%20Migration%20for%20Smart.pdf)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-green?style=flat-square)](https://www.python.org/downloads/)



## 📑 Table of Contents

- [Overview](#-overview)
- [Quick Start](#-quick-start)
- [Usage Examples](#-usage-examples)
- [Evaluation & Data](#-evaluation--data)
- [Project Structure](#-project-structure)
- [Citation](#-citation)
- [Ethical Considerations](#-ethical-considerations)

---

## 🔍 Overview

PoCShift is a migration-based PoC generation work that leverages existing PoCs to generate PoCs for contracts with similar vulnerabilities. It achieves both high precision and efficiency through a novel three-phase approach:

1. **PoC Abstraction**: Extracts essential components from existing PoCs.
2. **Candidate Matching**: Identifies contracts with similar vulnerable patterns.
3. **Migration Testing**: Generates and validates new PoCs in simulated environments.

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+ (tested on Windows 11)
- `pip` plus a virtual environment tool (`venv` or `conda`)
- Optional: [Foundry](https://book.getfoundry.sh/getting-started/installation) for replaying motivator traces

### Environment Setup

```bash
git clone https://github.com/kairanskrr/PoCShift.git
cd PoCShift
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate
pip install -r requirement.txt
```

> `setup.py` exposes the partial modules as a package, so you can also run `pip install -e .` if you need editable imports.

### Local Validation

- Inspect the **Onyx case study** under `motivating_example/` and replay the invocation trace with Foundry or your preferred tooling.
- Use the notebooks/scripts in `evaluation/rq2` and `evaluation/rq3` to reproduce oracle checks, template statistics, and successful-case aggregations.
- The partial `pocshift` package contains helper utilities (parser, abstraction, candidate matching) that can be invoked from custom research scripts.

---

## 🧪 Usage Examples

- **PoC abstraction sandbox**: call `AbstractedPoC` from `pocshift.poc_abstraction.poc_abstraction` with a PoC path plus metadata to obtain migratable signatures and ABI summaries.
- **Condition translation**: explore `pocshift/poc_abstraction/condition_translation` to see how environment pre/post conditions are normalized into reusable constraints.
- **Template analytics**: run `python evaluation/rq2/test_oracle.py` (adjusting paths at the bottom of the script) to regenerate vulnerability-type summaries used in RQ2.
- **Cross-tool comparison**: `evaluation/rq1` hosts PoCShift vs. ItyFuzz/Mythril logs so you can re-score true/false positives for your custom metrics.

---

## 📈 Evaluation & Data

- **RQ1 – PoC generation capability**: aggregated TP/FP/FN counts, execution logs, and reported-contract folders for PoCShift and baselines (`evaluation/rq1`).
- **RQ2 – Ablation / oracle quality**: scripts for trimming PoCs, extracting successful runs, and grouping by vulnerability type (`evaluation/rq2`).
- **RQ3 – Successful migration cases**: execution traces for the remaining validated vulnerable contracts (`evaluation/rq3`).
- **Motivating example**: detailed walkthrough of the Onyx Protocol exploit, including invocation traces and Algorithm 1 explanation (`motivating_example/README.md`).

Each folder keeps raw logs (`execution_logs/`) plus curated reports to ensure end-to-end reproducibility.

---

## 🗂️ Project Structure

```
PoCShift/
├── pocshift/                # Partial implementation (abstraction, matching, parsers)
├── evaluation/              # RQ1–RQ3 datasets, logs, scripts
├── motivating_example/      # Algorithm 1 case study & traces
├── full_paper/              # Camera-ready / preprint PDF
├── requirement.txt          # Python dependencies
├── setup.py                 # Editable install for partial modules
└── README.md                # You are here
```

---

## 📚Citation

If you use our work in your research, please kindly cite us as:

```bibtex
@article{pocshift2025,
  title     = {Learning from the Past: Real-World Exploit Migration for Smart Contract PoC Generation},
  author={Sun, Kairan and Xu, Zhengzi and Li, Kaixuan and Zhang, Lyuye and Wu, Daoyuan and Feng, Yebo and Liu, Yang},
  booktitle={Proceedings of the 40th IEEE/ACM International Conference on Automated Software Engineering},
  year={2025},
  series={ASE '25},
  publisher={IEEE},
}
```

---

## 🔐 Ethical Considerations

Due to ethical considerations, **the complete artifact** are not publicly released. The material here focuses on transparency for reviewers and researchers while preventing irresponsible use of automated exploit generation.

If you need the complete artifact, please send us an email (kairan.sun@ntu.edu.sg) with the purpose. Thanks for understanding.

In the email, please include a justification letter (PDF format) on official letterhead. The justification letter needs to acknowledge the "PoCShift" project from Nanyang Technological University and clearly state the reason for requesting the artifacts. Also, confirm that the shared resources **will not be redistributed without our permission**. We emphasize that we will ignore emails that do not follow the above instructions.
