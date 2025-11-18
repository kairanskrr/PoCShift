# PoC Generation Capability (RQ1)

This folder contains the evalution results for the PoC generation capability of PoCShift compared to the current SOTAs, the raw data of which is under `pocshift` and `sota` folder respectively. Below, we provide the summary of the evaluation results with *TP, FP*, and *FN*.

+ *TP (True Positive): Runnable PoC that successfully exploits vulnerabilities.*
+ *FP (False Positive): Runnable PoC but the target contract is not vulnerable/exploitable.*
+ *FN (False Negative): No runnable PoCs generated for exploitable vulnerabilities.*


## Updated Table II with FN and TN Numbers

We have added the complete Table II with explicit FN and TN counts below, along with important clarifications about these added metrics.


### Table II: Summary of PoC generation results (with FN and TN)

| Category (#GT) | ItyFuzz (TP, FP, FN) | Mythril (TP, FP, FN) | PoCShift (TP, FP, FN) |
|---------------|----------------------|----------------------|------------------------|
| AC (11)      | (2, 8, 9) | (0, 0, 11) | (11, 0, 0) |
| LF (18)      | (2, 0, 16) | (0, 0, 18) | (17, 0, 1) |
| PM (23)      | (4, 3, 19) | (0, 0, 23) | (19, 0, 4) |
| RE (1)       | (0, 0, 1) | (0, 0, 1) | (1, 0, 0) |
| AR (7)       | (0, 0, 7) | (0, 0, 7) | (7, 0, 0) |
| BM (7)       | (0, 0, 7) | (0, 0, 7) | (7, 0, 0) |
| **Total (67)** | **(8, 11, 59)** | **(0, 0, 67)** | **(62, 0, 5)** |
| **TN (Overall)** | **5,635** | **5,646** | **5,646** |

*#GT: number of ground truth vulnerabilities identified*  
*TP: True positive, FP: False positive, FN: False negative, TN: True negative*

### Clarifications on FN and TN

While we have provided FN and TN counts in the table, we focus primarily on TP/FP metrics as the most reliable indicators of the effectiveness of our approach. Due to the lack of comprehensive exploitable vulnerability annotations for smart contract, the ground truth vulnerabilities are based on vulnerabilities identified by PoCShift and SOTA tools and validated by human experts. This follows established practices in security research when ground truth is unavailable [1-3]. 

Following the established practice, we can reliably validate vulnerabilities that at least one tool identifies. TN and FN calculations would require comprehensive manual analysis of all 5,713 contracts to establish complete ground truth, which is a task beyond practical research scope and standard security evaluation practices. The current TN/FN values assume all non-flagged contracts are non-vulnerable, but this assumption cannot be verified without exhaustive expert assessment.

Our approach focuses precision-critical automation to generate runnable PoCs for only exploitable vulnerabilities while reducing false positives that burden security analysts. The zero false positive rate proves our method provides actionable evidence without manual verification overhead, addressing the core practical challenge in blockchain security assessment. This precision-focused evaluation directly corresponds to real-world deployment scenarios where analysts need trustworthy vulnerability identification rather than theoretical coverage completeness.



[1] Xiao, Yang, et al. "{MVP}: Detecting vulnerabilities using {Patch-Enhanced} vulnerability signatures." 29th USENIX Security Symposium (USENIX Security 20). 2020.\
[2] Kang, Wooseok, Byoungho Son, and Kihong Heo. "Tracer: Signature-based static analysis for detecting recurring vulnerabilities." Proceedings of the 2022 ACM SIGSAC Conference on Computer and Communications Security. 2022.\
[3] Feng, Siyue, et al. "{FIRE}: Combining {Multi-Stage} Filtering with Taint Analysis for Scalable Recurring Vulnerability Detection." 33rd USENIX Security Symposium (USENIX Security 24). 2024.
