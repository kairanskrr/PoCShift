# ✨PoCShift

PoCShift is a migration-based PoC generation work that leverages existing PoCs to generate PoCs for contracts with similar vulnerabilities. It achieves both high precision and efficiency through a novel three-phase approach:

1. **PoC Abstraction**: Extracts essential components from existing PoCs.
2. **Candidate Matching**: Identifies contracts with similar vulnerable patterns.
3. **Migration Testing**: Generates and validates new PoCs in simulated environments.

## About This Repository

This repository contains the **supplementary materials and evaluation artifacts** for our research paper on PoCShift. This repository is intended to support the reproducibility and verification of our research findings.

### Evaluation

Our evaluation dataset and results are available under ``\evaluation`` folder:

* ``\rq1``: In this folder, we provide the evaluation results for our tool and selected SOTA over the evaluation dataset. Among the results, ``\execution_logs`` contains the detailed execution logs for each tool while ``\reported`` contains the reported vulnerabilities by each tool.
* ``\rq2``: In this folder, we provide execution logs and scripts to conduct the ablative study for PoCShift.
* ``\rq3``: In this folder, we provide the execution logs for the rest successfully validated vulnerable contracts.

### Source Code Availability

Due to ethical considerations, **the complete source code of PoCShift will not be publicly released**. As PoCShift is designed to automatically generate Proof-of-Concept exploits for vulnerable smart contracts, unrestricted public access to the full implementation could potentially facilitate malicious activities and irresponsible vulnerability exploitation. The ``\pocshift`` folder contains a partial implementation for research transparency and reproducibility purposes.

For access requests or inquiries, please contact the authors through the contact information provided in our paper. Thank you!
