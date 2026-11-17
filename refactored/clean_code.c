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
