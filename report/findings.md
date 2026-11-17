# Dirty-Code Findings — Lab 3B / Experiment 4

## Source provenance and line numbering

The faculty-provided C snippet was pasted directly into the lab request. The prose header was not part of the C source. The exact 21-line C program was preserved unchanged as `original/dirty_code.c`.

SHA-256: `dae4262383e3aa96d80eb846015332425f36ad4a8198c7c6adb066a5fd472083`

| Line | Exact source |
|---:|---|
| 1 | `#include <stdio.h>` |
| 2 | `#include <string.h>` |
| 3 | `int main(void) {` |
| 4 | `char name[10];` |
| 5 | `strcpy(name, "Alexander Mishra");` |
| 6 | `int marks = 75;` |
| 7 | `if (marks > 50) {` |
| 8 | `if (marks < 100) {` |
| 9 | `if (marks == 75) {` |
| 10 | `printf("Excellent\n");` |
| 11 | `}` |
| 12 | `}` |
| 13 | `}` |
| 14 | `if (0) {` |
| 15 | `printf("Dead code\n");` |
| 16 | `}` |
| 17 | `FILE *fp = fopen("student.txt", "w");` |
| 18 | `fprintf(fp, "%s %d\n", name, marks);` |
| 19 | `fclose(fp);` |
| 20 | `return 0;` |
| 21 | `}` |

## Confirmed findings

| Finding ID | Dirty-code practice | Location | Explanation | Security consequence | Standard | Rule identifier | Remediation |
|---|---|---|---|---|---|---|---|
| F-01 | Unsafe string function and definite stack buffer overflow | Lines 4–5: `char name[10];` followed by `strcpy(name, "Alexander Mishra");` | `"Alexander Mishra"` is 16 characters plus the terminating null byte, so 17 bytes are written into a 10-byte stack array. `strcpy()` performs no destination-bound check. GCC also emitted `-Wstringop-overflow=`: “writing 17 bytes into a region of size 10”. cppcheck reported `bufferAccessOutOfBounds` at line 5. | Undefined behaviour, stack corruption, abnormal termination (the original aborted with `*** stack smashing detected ***`, exit 134 in the recorded test), and in other builds a potential path to arbitrary code execution. | CERT C; MISRA C:2012 (Amendment 1) | CERT **STR31-C** (Rule; High severity, L2). MISRA **Rule 21.17** (Mandatory). | Enlarged the destination to a named 64-byte buffer, replaced `strcpy()` with `snprintf()` using an explicit size, checked the return value for encoding/truncation failure, and added a `_Static_assert` that the default name plus terminator fits. |
| F-02 | Magic numbers / unexplained literals | Lines 4, 6, 7, 8 and 9: `10`, `75`, `50`, `100`, `75`. Line 17 also hard-codes `"student.txt"`. | The buffer size, default mark, validation thresholds, distinction mark and output filename are embedded directly in program logic. Changing one occurrence without another can silently break size or validation assumptions. cppcheck did not report this category. | Inconsistent boundary handling and fragile maintenance; a changed buffer size can reintroduce overflow if call sites are missed. | CERT C (advisory recommendation) | CERT **DCL06-C** (Recommendation/advisory; Low severity, L3). No direct MISRA rule is asserted here. OWASP has no verified low-level C identifier for this practice. | Introduced `NAME_BUFFER_SIZE`, `DEFAULT_MARK`, `MIN_PASSING_MARK`, `MAX_MARK`, `DISTINCTION_MARK`, `OUTPUT_FILENAME`, `EXCELLENT_MESSAGE` and `ARGUMENT_COUNT_WITH_INPUTS`. |
| F-03 | Invariant conditions and unnecessary deep nesting | Lines 7–13: `if (marks > 50)`, `if (marks < 100)`, `if (marks == 75)` | `marks` is assigned the literal `75` at line 6 and never modified, so all three controlling expressions are always true. cppcheck reported `knownConditionTrueFalse` at lines 7, 8 and 9 with notes tracing the value to line 6. Three nested blocks add no decision value. | Obscures real logic, makes future range changes error-prone, and can be removed by a compiler; defensive or intended branches may be lost during maintenance. | MISRA C:2012 | MISRA **Rule 14.3** (Required): controlling expressions shall not be invariant. | Added explicit range validation for supplied marks, reduced the three nested tests to a single `has_distinction(mark)` equality check, and used one exit path with checked errors. |
| F-04 | Dead / unreachable code | Lines 14–16: `if (0) { printf("Dead code\n"); }` | The controlling expression is the integer constant `0`, so the body can never execute. cppcheck did not emit a diagnostic for this block. | Misleading documentation of intent, hides obsolete logic, and may indicate an unfinished or accidentally disabled feature. | CERT C; MISRA C:2012 | CERT **MSC12-C** (Recommendation/advisory; Low severity, L3). MISRA **Rule 2.1** (Required, unreachable code), **Rule 2.2** (Required, no dead code) and **Rule 14.3** (Required, invariant controlling expression). | Removed the entire `if (0)` block. No behaviour was lost because it was unreachable. |
| F-05 | Unchecked function return values and improper error handling | Line 10: `printf(...)`; lines 17–19: `fopen()`, `fprintf()`, `fclose()` | `fopen()` can return `NULL`, and `fprintf()`/`fclose()` can report failure through negative/EOF returns. The original dereferences `fp` without checking it; cppcheck reported `nullPointerOutOfResources` at lines 18 and 19. The `printf()` result is also unused, although CERT ERR33-C-EX1 permits ignoring output directed to stdout. | Null-pointer dereference or undefined behaviour on resource exhaustion, silent data loss if the write or close fails, and no useful failure signal to the caller. | CERT C; MISRA C:2012 | CERT **ERR33-C** (Rule; High severity, L1). MISRA **Directive 4.7** (Required) and **Rule 17.7** (Required). | Checked `fopen()` for `NULL`, checked `fprintf()` for a negative return, checked `fclose()` for non-zero, reported errors on `stderr`, and returned `EXIT_FAILURE`. The refactor also checks the `printf()` result despite the CERT stdout exception. |
| F-06 | Absence of an input-validation and error-policy boundary | Lines 3, 6 and 17–19 (structural) | The only “inputs” in the original are hard-coded values, so there is no validation boundary and no way to test invalid data. This is a design/maintainability weakness rather than a claim that external input was present and ignored. | A future change that introduces real input could reuse the unchecked copy and unchecked file operations, converting the existing buffer overflow into an attacker-controlled one. | CERT C; MISRA C:2012 | CERT **STR31-C** and **ERR33-C**; MISRA **Directive 4.7**, **Rules 14.3, 17.7, 21.17**. | Added a documented validation boundary in `load_student_data()` and `parse_mark()`: optional `name mark` arguments, non-empty name, bounded length, numeric mark with `strtol()` and `ERANGE`/trailing-character checks, and inclusive 50–100 range enforcement. Invalid input exits with `EXIT_FAILURE` before any file write. |

## Categories inspected but not confirmed

The following requested categories were checked against every source line and are **not** reported as findings because the faculty source does not contain them:

- `gets()`, `strcat()` or `sprintf()` — only `strcpy()` appears.
- Poor variable or function naming — `name`, `marks`, `fp` and `main` are conventional and readable in this small program.
- Duplicated or unnecessary code beyond the confirmed invariant/dead constructs above — no repeated statements or equivalent functions were found.
- Suppressed compiler warnings — no `#pragma`, diagnostic-suppression flag or warning-disable directive appears.
- Missing input validation in the original — there is no external input path. The refactor adds validation to support representative valid/invalid testing; this is recorded as a design improvement, not as a fabricated original defect.
- OWASP mapping — OWASP guidance addresses web-application risks and provides no verified identifier for these low-level C language practices. CERT C and MISRA C are the applicable standards here.

## Rule verification references

- CERT DCL06-C: https://cmu-sei.github.io/secure-coding-standards/sei-cert-c-coding-standard/recommendations/declarations-and-initialization-dcl/dcl06-c/
- CERT STR31-C: https://cmu-sei.github.io/secure-coding-standards/sei-cert-c-coding-standard/rules/characters-and-strings-str/str31-c
- CERT MSC12-C: https://cmu-sei.github.io/secure-coding-standards/sei-cert-c-coding-standard/recommendations/miscellaneous-msc/msc12-c/
- CERT ERR33-C: https://cmu-sei.github.io/secure-coding-standards/sei-cert-c-coding-standard/rules/error-handling-err/err33-c
- MISRA C:2012 main guidelines and Appendix A (Rules 2.1, 2.2, 14.3, 17.7; Directive 4.7): MISRA C:2012 guidelines, https://www.misra.org.uk/
- MISRA C:2012 Amendment 1 (Rule 21.17, Mandatory): https://misra.org.uk/app/uploads/2021/06/MISRA-C-2012-AMD1.pdf

### Mandatory / required / advisory distinction

- **Mandatory**: MISRA Rule 21.17. It permits no deviation in a MISRA compliance claim.
- **Required**: MISRA Rules 2.1, 2.2, 14.3, 17.7 and Directive 4.7. They shall be met unless a formal, documented deviation is approved.
- **Rule**: CERT STR31-C and ERR33-C are normative CERT rules. CERT assigns STR31-C High/L2 and ERR33-C High/L1 risk ratings.
- **Recommendation (advisory)**: CERT DCL06-C and MSC12-C are guidance rather than normative rules; CERT assigns both Low/L3.
