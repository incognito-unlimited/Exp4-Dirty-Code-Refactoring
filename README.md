# Exp4 — Dirty-Code Analysis and Standards-Compliant Refactoring

**Lab designation:** Lab 3B  
**Experiment:** 4  
**Subject:** Secure Coding and Vulnerabilities  
**Student:** Aditey Mehra  
**Roll number:** 2301730266  
**University:** K.R. Mangalam University  
**Programme:** B.Tech CSE (AI & ML)  
**Section:** D  
**Semester:** 7  

## Aim

Analyse the exact faculty-provided dirty C source, identify every confirmed dirty-code practice, map each finding to verified CERT C / MISRA C guidance, refactor the program safely, compare cppcheck diagnostics before and after, verify functionality, publish evidence to GitHub and populate the supplied editable DOCX template.

## Objectives

1. Preserve the unchanged faculty source with original line numbers.
2. Report only practices that are actually present in that source.
3. Verify every rule identifier and distinguish mandatory, required, advisory and CERT rule/recommendation categories.
4. Replace unsafe string handling, magic numbers, invariant/dead logic and unchecked library calls.
5. Run the same cppcheck version and options before and after refactoring.
6. Compile both versions and record real outputs and exit statuses.
7. Capture ten genuine screenshots and publish the complete project.

## Original code overview

`original/dirty_code.c` is the exact 21-line snippet supplied in the lab request. It declares a 10-byte stack buffer, copies a 17-byte string into it with `strcpy()`, sets a hard-coded mark to 75, evaluates three always-true nested conditions, contains an `if (0)` dead branch and writes to `student.txt` without checking `fopen()`, `fprintf()` or `fclose()`.

SHA-256: `dae4262383e3aa96d80eb846015332425f36ad4a8198c7c6adb066a5fd472083`

## Findings summary

| ID | Confirmed practice | Original lines | Key standard |
|---|---|---|---|
| F-01 | `strcpy()` into a 10-byte buffer; definite stack overflow | 4–5 | CERT STR31-C; MISRA 21.17 |
| F-02 | Magic numbers and hard-coded literals | 4, 6, 7, 8, 9, 17 | CERT DCL06-C (advisory) |
| F-03 | Invariant conditions and three-level nesting | 7–13 | MISRA 14.3 |
| F-04 | Unreachable/dead `if (0)` block | 14–16 | CERT MSC12-C; MISRA 2.1, 2.2, 14.3 |
| F-05 | Unchecked `printf`/`fopen`/`fprintf`/`fclose` returns | 10, 17–19 | CERT ERR33-C; MISRA Dir 4.7, Rule 17.7 |
| F-06 | No validation/error-policy boundary | 3, 6, 17–19 (structural) | CERT STR31-C/ERR33-C; MISRA Dir 4.7 |

No `gets()`, `strcat()` or `sprintf()` call, poor naming, duplicated code, warning suppression or external-input path was present. Those categories were inspected and deliberately not reported as findings. Full analysis: `report/findings.md`.

## Coding-standard mapping

| Identifier | Category | Meaning | Applied to |
|---|---|---|---|
| CERT STR31-C | Rule, High/L2 | Guarantee sufficient string storage including the null terminator | F-01, F-06 |
| CERT DCL06-C | Recommendation/advisory, Low/L3 | Use meaningful symbolic constants for literal values | F-02 |
| CERT MSC12-C | Recommendation/advisory, Low/L3 | Detect and remove code with no effect or never executed | F-04 |
| CERT ERR33-C | Rule, High/L1 | Detect and handle standard library errors | F-05, F-06 |
| MISRA C:2012 Rule 21.17 | Mandatory | String-library use shall not access beyond referenced object bounds | F-01 |
| MISRA C:2012 Rule 2.1 | Required | No unreachable code | F-04 |
| MISRA C:2012 Rule 2.2 | Required | No dead code | F-04 |
| MISRA C:2012 Rule 14.3 | Required | Controlling expressions shall not be invariant | F-03, F-04 |
| MISRA C:2012 Rule 17.7 | Required | Non-void return values shall be used | F-05 |
| MISRA C:2012 Directive 4.7 | Required | Error information returned by functions shall be tested | F-05, F-06 |

OWASP does not provide a verified identifier for these low-level C language practices; its guidance targets web-application risk categories. CERT C and MISRA C are the applicable standards. The original also violates MISRA Rule 21.6 by using standard I/O functions, but that rule is a general restriction rather than a rule about the dirty practice being fixed here; the refactor therefore does not claim full MISRA compliance.

## Refactoring explanation

1. Replaced literals with enumeration constants and macros; added a compile-time size assertion.
2. Removed `#include <string.h>` and the unsafe `strcpy()` call. `snprintf()` writes with an explicit destination size; its return value detects encoding failure and truncation.
3. Added a validation boundary: optional `name mark` arguments, non-empty/bounded name, `strtol()` parsing with `ERANGE` and trailing-character checks, and inclusive 50–100 range enforcement.
4. Flattened the three nested invariant conditions into one `has_distinction()` check after range validation.
5. Removed the unreachable `if (0)` block.
6. Checked `printf()`, `fopen()`, `fprintf()` and `fclose()` results and returned `EXIT_SUCCESS`/`EXIT_FAILURE` appropriately.
7. Used descriptive helper names and a single, readable main flow. No warning suppression was added or retained.

**Documented behaviour change:** the no-argument invocation still prints `Excellent` and writes `Alexander Mishra 75` to `student.txt`, preserving the intended default behaviour. Optional arguments are an additive extension used to exercise valid and invalid inputs; the original ignored arguments and had no validation.

## Cppcheck commands

```bash
cppcheck --version
cppcheck --enable=all --inconclusive --std=c11 --suppress=missingIncludeSystem --template=gcc original/dirty_code.c 2>&1
cppcheck --enable=all --inconclusive --std=c11 --suppress=missingIncludeSystem --template=gcc refactored/clean_code.c 2>&1
```

Tool: Cppcheck 2.19.0. Both runs exited 0 because `--error-exitcode` was not used. Complete output is in `evidence/cppcheck_before.txt` and `evidence/cppcheck_after.txt`.

## Cppcheck results

| Metric | Original | Refactored |
|---|---:|---:|
| Errors | 0 | 0 |
| Warnings | 6 | 0 |
| Style findings | 0 | 0 |
| Performance findings | 0 | 0 |
| Portability findings | 0 | 0 |
| **Total findings** | **6** | **0** |

Original IDs: `bufferAccessOutOfBounds` (×1), `knownConditionTrueFalse` (×3), `nullPointerOutOfResources` (×2). All were resolved with no newly introduced findings. The informational `[checkersReport]` line is not counted. Cppcheck did not report the dead `if (0)` block, unchecked `fprintf()`/`fclose()` returns or magic numbers; these were confirmed by source review. See `evidence/cppcheck_comparison.txt`.

## Functional testing

```bash
gcc -Wall -Wextra -std=c11 -g original/dirty_code.c -o build/original_program
gcc -Wall -Wextra -std=c11 -g refactored/clean_code.c -o build/refactored_program
```

- Original compilation emitted `-Wstringop-overflow=` for 17 bytes into a 10-byte region; exit 0.
- Refactored compilation produced no diagnostics; exit 0.
- Original no-argument run: no stdout, `*** stack smashing detected ***`, exit 134; `student.txt` contained `Alexander Mishra 75` before abort.
- Refactored no-argument run: stdout `Excellent`, exit 0; `student.txt` contained `Alexander Mishra 75`.
- Refactored valid custom input `Ada Lovelace 82`: exit 0, file `Ada Lovelace 82`.
- Refactored boundary input `Boundary Student 50`: exit 0, file `Boundary Student 50`.
- Invalid mark `101`, non-numeric mark `abc`, over-long name and wrong argument count: usage message on stderr, exit 1, no `student.txt`.

Complete transcript: `evidence/functional_tests.txt`.

## Repository structure

```text
Exp4-Dirty-Code-Refactoring/
├── original/dirty_code.c
├── refactored/clean_code.c
├── evidence/
│   ├── cppcheck_before.txt
│   ├── cppcheck_after.txt
│   ├── cppcheck_comparison.txt
│   ├── functional_tests.txt
│   ├── tool_versions.txt
│   └── screenshots/ (01-10 genuine PNG captures)
├── report/
│   ├── findings.md
│   ├── Lab3B_Report.md
│   └── Lab_3B_Exp4_Dirty_Code_Refactoring_Aditey_Mehra.docx
├── README.md
└── .gitignore
```

## GitHub repository

https://github.com/incognito-unlimited/Exp4-Dirty-Code-Refactoring
