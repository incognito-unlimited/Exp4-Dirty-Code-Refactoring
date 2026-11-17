# Lab 3B — Experiment 4 Laboratory Report

**Dirty-Code Analysis and Standards-Compliant Refactoring**

| Field | Value |
|---|---|
| Submitted by | Aditey Mehra |
| Roll Number | 2301730266 |
| University | K.R. Mangalam University |
| Programme | B.Tech CSE (AI & ML) |
| Section | D |
| Semester | 7 |
| Subject | Secure Coding and Vulnerabilities |
| Experiment | 4 / Lab 3B |

## 1. Aim

To analyse the exact faculty-provided C snippet for dirty-code practices, classify each confirmed finding by location, security consequence and applicable coding-standard guidance, refactor the code into a cleaner and safer implementation, and compare cppcheck diagnostics before and after refactoring.

## 2. Objectives

- Inspect the exact faculty-provided source and record original line numbers.
- Identify confirmed dirty-code practices without inventing absent categories.
- Map findings to verified CERT C and MISRA C guidance, distinguishing rule types.
- Refactor while preserving the intended no-argument program behaviour.
- Run cppcheck before and after with the same version and options.
- Compile both versions, run representative tests and record actual results.
- Publish the source, evidence, reports and screenshots to GitHub.

## 3. Introduction

The supplied program demonstrates how several small readability and safety problems combine into a serious defect. A 10-byte stack buffer receives a 17-byte string via `strcpy()`, producing a definite buffer overflow. Hard-coded thresholds produce invariant conditions, an `if (0)` branch is unreachable, and standard library failures are ignored. Dirty code of this kind is difficult to review because the reader cannot easily separate intentional constants from accidental ones, live logic from obsolete logic, or successful operations from unchecked failures.

OWASP guidance was considered, but it addresses web-application risk categories and provides no verified identifier for these low-level C practices. CERT C and MISRA C are the applicable standards.

## 4. Analysis Methodology

1. Preserved the exact 21-line snippet as `original/dirty_code.c` (SHA-256 `dae4262383e3aa96d80eb846015332425f36ad4a8198c7c6adb066a5fd472083`).
2. Inspected every line against the twelve requested practice categories.
3. Verified CERT and MISRA identifiers against CERT/SEI and MISRA publications.
4. Ran `cppcheck --version`, then cppcheck 2.19.0 with identical options on both files.
5. Refactored the code and reran cppcheck with the same command form.
6. Compiled both versions with GCC 15.2.0 and captured stdout, stderr, exit statuses and generated files.
7. Captured ten genuine screenshots and verified the GitHub upload.

## 5. Findings Table

See `report/findings.md` for the complete issue-by-issue table. Summary:

| ID | Practice | Lines | Standard / identifier |
|---|---|---|---|
| F-01 | Unsafe `strcpy()` and stack buffer overflow | 4–5 | CERT STR31-C; MISRA 21.17 (Mandatory) |
| F-02 | Magic numbers and hard-coded literals | 4, 6, 7, 8, 9, 17 | CERT DCL06-C (advisory) |
| F-03 | Invariant conditions and deep nesting | 7–13 | MISRA 14.3 (Required) |
| F-04 | Dead/unreachable code | 14–16 | CERT MSC12-C; MISRA 2.1, 2.2, 14.3 |
| F-05 | Unchecked library returns / improper error handling | 10, 17–19 | CERT ERR33-C; MISRA Dir 4.7, Rule 17.7 |
| F-06 | No validation/error-policy boundary | structural | CERT STR31-C/ERR33-C; MISRA Dir 4.7 |

Not confirmed: `gets()`, `strcat()`, `sprintf()`, poor naming, duplicated code, warning suppression and missing external-input validation. No finding or line number was invented.

## 6. Original Source Code

File: `original/dirty_code.c` (complete, unchanged, 21 lines)

```c
#include <stdio.h>
#include <string.h>
int main(void) {
char name[10];
strcpy(name, "Alexander Mishra");
int marks = 75;
if (marks > 50) {
if (marks < 100) {
if (marks == 75) {
printf("Excellent\n");
}
}
}
if (0) {
printf("Dead code\n");
}
FILE *fp = fopen("student.txt", "w");
fprintf(fp, "%s %d\n", name, marks);
fclose(fp);
return 0;
}
```

## 7. Refactored Source Code

File: `refactored/clean_code.c` (complete)

```c
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#define OUTPUT_FILENAME "student.txt"
#define DEFAULT_STUDENT_NAME "Alexander Mishra"
#define EXCELLENT_MESSAGE "Excellent\n"
#define ARGUMENT_COUNT_WITH_INPUTS 3

enum {
    NAME_BUFFER_SIZE = 64,
    DEFAULT_MARK = 75,
    MIN_PASSING_MARK = 50,
    MAX_MARK = 100,
    DISTINCTION_MARK = 75
};

_Static_assert(sizeof(DEFAULT_STUDENT_NAME) <= NAME_BUFFER_SIZE,
               "NAME_BUFFER_SIZE must hold the default student name and its terminator");

static int copy_student_name(char *destination, size_t destination_size, const char *source)
{
    int written;

    if ((destination == NULL) || (source == NULL) || (destination_size == 0u)) {
        return 0;
    }
    if (source[0] == '\0') {
        return 0;
    }

    written = snprintf(destination, destination_size, "%s", source);
    if ((written < 0) || ((size_t)written >= destination_size)) {
        return 0;
    }
    return 1;
}

static int parse_mark(const char *text, int *mark)
{
    char *end_of_number = NULL;
    long parsed_value;

    if ((text == NULL) || (mark == NULL) || (text[0] == '\0')) {
        return 0;
    }

    errno = 0;
    parsed_value = strtol(text, &end_of_number, 10);
    if ((errno == ERANGE) || (end_of_number == text) || (*end_of_number != '\0')) {
        return 0;
    }
    if ((parsed_value < MIN_PASSING_MARK) || (parsed_value > MAX_MARK)) {
        return 0;
    }

    *mark = (int)parsed_value;
    return 1;
}

static int has_distinction(int mark)
{
    /* load_student_data() has already validated the inclusive 50-100 range. */
    return mark == DISTINCTION_MARK;
}

static int load_student_data(int argc, char *argv[], char *student_name,
                             size_t student_name_size, int *mark)
{
    if (argc == 1) {
        *mark = DEFAULT_MARK;
        return copy_student_name(student_name, student_name_size, DEFAULT_STUDENT_NAME);
    }

    if (argc != ARGUMENT_COUNT_WITH_INPUTS) {
        return 0;
    }
    return copy_student_name(student_name, student_name_size, argv[1]) &&
           parse_mark(argv[2], mark);
}

int main(int argc, char *argv[])
{
    char student_name[NAME_BUFFER_SIZE] = {0};
    int mark = 0;
    FILE *student_file = NULL;

    if (!load_student_data(argc, argv, student_name, sizeof(student_name), &mark)) {
        const char *program_name = "refactored";
        if ((argc > 0) && (argv[0] != NULL)) {
            program_name = argv[0];
        }
        fprintf(stderr, "Invalid arguments. Use: %s [name mark]\n", program_name);
        return EXIT_FAILURE;
    }

    if (has_distinction(mark)) {
        int print_result = printf(EXCELLENT_MESSAGE);
        if (print_result < 0) {
            fprintf(stderr, "Failed to write the result to stdout.\n");
            return EXIT_FAILURE;
        }
    }

    student_file = fopen(OUTPUT_FILENAME, "w");
    if (student_file == NULL) {
        fprintf(stderr, "Failed to open %s for writing.\n", OUTPUT_FILENAME);
        return EXIT_FAILURE;
    }

    if (fprintf(student_file, "%s %d\n", student_name, mark) < 0) {
        fprintf(stderr, "Failed to write student data to %s.\n", OUTPUT_FILENAME);
        if (fclose(student_file) != 0) {
            fprintf(stderr, "Additionally failed to close %s.\n", OUTPUT_FILENAME);
        }
        return EXIT_FAILURE;
    }

    if (fclose(student_file) != 0) {
        fprintf(stderr, "Failed to close %s after writing.\n", OUTPUT_FILENAME);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
```

### Significant modifications

- Named constants replaced unexplained literals; a `_Static_assert` ties buffer size to the default name.
- `strcpy()` was removed; bounded `snprintf()` with checked return values prevents overflow and detects truncation.
- Optional command-line inputs and `parse_mark()` add validation using `strtol()`, `ERANGE` and range checks.
- The three nested invariant tests became one equality check after range validation.
- The dead `if (0)` block was removed.
- `printf()`, `fopen()`, `fprintf()` and `fclose()` return values are handled.
- `EXIT_SUCCESS`/`EXIT_FAILURE` replaced raw `0`.

**Behaviour change:** the no-argument mode is preserved. Optional arguments are additive and exist so that valid and invalid inputs can be tested; they do not alter the default output.

## 8. Coding-Standard Mapping

| Finding | Standard | Exact identifier | Category / applicability |
|---|---|---|---|
| F-01 | CERT C | STR31-C | Rule; High/L2. Destination must hold all characters plus null terminator. |
| F-01 | MISRA C:2012 (AMD1) | Rule 21.17 | Mandatory. String-library calls must not access outside object bounds. |
| F-02 | CERT C | DCL06-C | Recommendation/advisory; Low/L3. |
| F-03 | MISRA C:2012 | Rule 14.3 | Required. Controlling expressions must not be invariant. |
| F-04 | CERT C | MSC12-C | Recommendation/advisory; Low/L3. |
| F-04 | MISRA C:2012 | Rules 2.1, 2.2, 14.3 | Required. No unreachable code, no dead code, no invariant control. |
| F-05 | CERT C | ERR33-C | Rule; High/L1. `fopen`, `fprintf` to a file and `fclose` results are not exempt. |
| F-05 | MISRA C:2012 | Directive 4.7, Rule 17.7 | Required. Error information shall be tested; non-void returns shall be used. |
| F-06 | CERT C / MISRA C | STR31-C, ERR33-C, Dir 4.7 | Validation boundary added; no external input existed in the original. |

CERT `ERR33-C-EX1` permits ignoring `printf()` output directed to stdout, so line 10 was not treated as a CERT violation; MISRA Rule 17.7 still applies, and the refactor checks the result. OWASP has no applicable verified identifier for these C-language issues.

## 9. Cppcheck Analysis — Before and After

Version: `Cppcheck 2.19.0`. Command used for each file:

```bash
cppcheck --enable=all --inconclusive --std=c11 --suppress=missingIncludeSystem --template=gcc <file> 2>&1
```

Both exited 0. The informational `[checkersReport]` line is excluded from counts.

| Metric | Original | Refactored |
|---|---:|---:|
| Errors | 0 | 0 |
| Warnings | 6 | 0 |
| Style findings | 0 | 0 |
| Performance findings | 0 | 0 |
| Portability findings | 0 | 0 |
| **Total** | **6** | **0** |

Original diagnostics: `bufferAccessOutOfBounds` line 5; `knownConditionTrueFalse` lines 7, 8 and 9; `nullPointerOutOfResources` lines 18 and 19. All were resolved; none remain and none were newly introduced. Cppcheck did not report the dead branch, unchecked write/close returns or magic numbers; these were found by manual inspection. Complete logs: `evidence/cppcheck_before.txt`, `evidence/cppcheck_after.txt`, `evidence/cppcheck_comparison.txt`.

## 10. Functional Verification

Compiler: `gcc (Ubuntu 15.2.0-16ubuntu1) 15.2.0`. System: Ubuntu 26.04.1 LTS, Linux 6.18.58.1-microsoft-standard-WSL2.

| Test | Program / input | stdout | stderr | Exit | `student.txt` |
|---|---|---|---|---:|---|
| 1 | Original, no args | *(empty)* | `*** stack smashing detected ***: terminated` | 134 | `Alexander Mishra 75` |
| 2 | Original, extra args | *(empty)* | `*** stack smashing detected ***: terminated` | 134 | `Alexander Mishra 75` |
| 3 | Refactored, no args | `Excellent` | *(empty)* | 0 | `Alexander Mishra 75` |
| 4 | Refactored, `Ada Lovelace 82` | *(empty)* | *(empty)* | 0 | `Ada Lovelace 82` |
| 5 | Refactored, `Boundary Student 50` | *(empty)* | *(empty)* | 0 | `Boundary Student 50` |
| 6 | Refactored, `Invalid Mark 101` | *(empty)* | usage message | 1 | not created |
| 7 | Refactored, `Invalid Mark abc` | *(empty)* | usage message | 1 | not created |
| 8 | Refactored, over-long name + `75` | *(empty)* | usage message | 1 | not created |
| 9 | Refactored, one argument only | *(empty)* | usage message | 1 | not created |

The original's buffered `printf()` output was not flushed before abort, which is why stdout is empty in tests 1–2 even though the file write completed. The refactored default run preserves the intended output and file content. Full transcript: `evidence/functional_tests.txt`.

## 11. GitHub Repository

https://github.com/incognito-unlimited/Exp4-Dirty-Code-Refactoring

## 12. Result

The exact faculty source was preserved and all six confirmed findings were documented with verified standard identifiers. Refactoring removed the definite stack overflow, dead and invariant logic, and unchecked file-operation failures. Cppcheck 2.19.0 reported six warnings before refactoring and zero findings afterwards. Both versions compiled; the original aborted with stack-smashing detection while the refactored program completed valid runs and rejected invalid inputs with exit status 1. Ten genuine screenshots and all evidence files were published to the repository.

## 13. Conclusion

The experiment shows that manual source review and static analysis are complementary. Cppcheck reliably detected the buffer overflow, invariant conditions and possible null dereferences, but it did not report the dead `if (0)` block, unchecked `fprintf()`/`fclose()` returns or magic numbers. Standards-based review supplied those mappings and ensured that the fixes addressed root causes rather than only tool messages. The refactored program preserves the intended default behaviour while adding bounded string handling, validation, clear control flow and complete error handling.
