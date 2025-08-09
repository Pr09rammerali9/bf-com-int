#include <stdio.h>
#include <stdlib.h>                               #include <string.h>
#include <unistd.h>                               #include <sys/syscall.h>                                                                            #define TAPE_SIZE 30000                           #define MAX_FUNCTIONS 100                         #define MAX_FUNC_NAME_LEN 64                      #define MAX_CALL_STACK_DEPTH 1000                 #define MAX_INCLUDED_FILES 100
                                                  unsigned char tape[TAPE_SIZE] = {0};
unsigned char *dp = tape;
FILE *file_handle = NULL;                                                                           typedef struct {                                      char name[MAX_FUNC_NAME_LEN];
    size_t ip_start;                              } Function;
                                                  Function function_table[MAX_FUNCTIONS];
int function_count = 0;                                                                             size_t call_stack[MAX_CALL_STACK_DEPTH];          int stack_pointer = 0;                                                                              char included_files[MAX_INCLUDED_FILES][256];
int included_files_count = 0;

int is_included(const char *filename) {
    for (int i = 0; i < included_files_count; i++) {
        if (strcmp(included_files[i], filename) == 0) {
            return 1;
        }
    }
    return 0;
}

void add_included(const char *filename) {
    if (included_files_count < MAX_INCLUDED_FILES) {
        strcpy(included_files[included_files_count], filename);
        included_files_count++;
    }
}

char* read_file_to_string(const char* filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Could not open file");
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *code = malloc(file_size + 1);
    if (!code) {
        perror("Memory allocation failed");
        fclose(file);
        return NULL;
    }

    fread(code, 1, file_size, file);
    code[file_size] = '\0';
    fclose(file);
    return code;
}

char* preprocess_code(const char* code_in, const char* current_file) {
    char* code_out = strdup(code_in);
    size_t ip = 0;
    while (ip < strlen(code_out)) {
        if (code_out[ip] == '%') {
            if (strncmp(&code_out[ip + 1], "inc", 3) == 0 || strncmp(&code_out[ip + 1], "grd", 3) == 0) {
                int is_guarded = (strncmp(&code_out[ip + 1], "grd", 3) == 0);

                size_t filename_start = ip + 5;
                char filename[256];
                size_t j = 0;
                while (code_out[filename_start + j] != '\n' && code_out[filename_start + j] != '\0' && j < 255) {
                    filename[j] = code_out[filename_start + j];
                    j++;
                }
                filename[j] = '\0';

                size_t directive_len = 5 + j;

                if (is_guarded && is_included(filename)) {
                    char* temp = malloc(strlen(code_out) - directive_len + 1);
                    strncpy(temp, code_out, ip);
                    strcpy(temp + ip, code_out + ip + directive_len);
                    free(code_out);
                    code_out = temp;
                    continue;
                }

                if (is_guarded) {
                    add_included(filename);
                }

                char* included_code = read_file_to_string(filename);
                if (included_code) {
                    char* temp = malloc(strlen(code_out) + strlen(included_code) - directive_len + 1);
                    strncpy(temp, code_out, ip);
                    strcpy(temp + ip, included_code);
                    strcpy(temp + ip + strlen(included_code), code_out + ip + directive_len);
                    free(code_out);
                    free(included_code);
                    code_out = temp;
                } else {
                    fprintf(stderr, "Error: Could not include file '%s'\n", filename);
                    exit(1);
                }
            }
        }
        ip++;
    }
    return code_out;
}

void register_functions(char *code) {
    size_t ip = 0;
    while (code[ip] != '\0') {
        if (code[ip] == '{') {
            ip++;
            strcpy(function_table[function_count].name, (char*)dp);
            function_table[function_count].ip_start = ip;
            function_count++;
            size_t inner_braces = 1;
            while (inner_braces > 0) {
                if (code[ip] == '{') inner_braces++;
                if (code[ip] == '}') inner_braces--;
                ip++;
            }
        }
        ip++;
    }
}

void interpret(char *code) {
    size_t ip = 0;
    size_t loop_counter = 0;
    register_functions(code);
    ip = 0;

    while (code[ip] != '\0') {
        switch (code[ip]) {
            case '>':
                dp++;
                break;
            case '<':
                dp--;
                break;
            case '+':
                (*dp)++;
                break;
            case '-':
                (*dp)--;
                break;
            case '.':
                putchar(*dp);
                break;
            case ',':
                *dp = (unsigned char)getchar();
                break;
            case '[':
                if (*dp == 0) {
                    loop_counter = 1;
                    while (loop_counter > 0) {
                        ip++;
                        if (code[ip] == '[') loop_counter++;
                        if (code[ip] == ']') loop_counter--;
                    }
                }
                break;
            case ']':
                if (*dp != 0) {
                    loop_counter = 1;
                    while (loop_counter > 0) {
                        ip--;
                        if (code[ip] == ']') loop_counter++;
                        if (code[ip] == '[') loop_counter--;
                    }
                }
                break;
            case '$':
                if (file_handle != NULL) {
                    fclose(file_handle);
                }
                file_handle = fopen((char*)dp, "r+");
                if (file_handle == NULL) {
                    perror("Could not open file");
                    exit(1);
                }
                break;
            case '~':
                if (file_handle != NULL) {
                    fclose(file_handle);
                    file_handle = NULL;
                }
                break;
            case '#':
                if (file_handle != NULL) {
                    fputc(*dp, file_handle);
                }
                break;
            case '^':
                if (file_handle != NULL) {
                    int c = fgetc(file_handle);
                    if (c != EOF) {
                        *dp = (unsigned char)c;
                    } else {
                        *dp = 0;
                    }
                }
                break;
            case '!':
                {
                    long syscall_num = *dp;
                    long arg1 = *(dp + 1);
                    long arg2 = *(dp + 2);
                    long arg3 = *(dp + 3);
                    syscall(syscall_num, arg1, arg2, arg3);
                    dp += 4;
                }
                break;
            case '{':
                {
                    size_t brace_counter = 1;
                    while (brace_counter > 0) {
                        ip++;
                        if (code[ip] == '{') brace_counter++;
                        if (code[ip] == '}') brace_counter--;
                    }
                }
                break;
            case '}':
            case '_':
                if (stack_pointer > 0) {
                    ip = call_stack[--stack_pointer];
                } else {
                    ip = strlen(code);
                }
                break;
            case '@':
                {
                    char func_name[MAX_FUNC_NAME_LEN];
                    strcpy(func_name, (char*)dp);
                    int found = 0;
                    for (int i = 0; i < function_count; i++) {
                        if (strcmp(function_table[i].name, func_name) == 0) {
                            call_stack[stack_pointer++] = ip + 1;
                            ip = function_table[i].ip_start;
                            found = 1;
                            break;
                        }
                    }
                    if (!found) {
                        fprintf(stderr, "Error: Unknown function '%s'\n", func_name);
                        exit(1);
                    }
                    break;
                }
            case '"':
                if (strncmp(&code[ip + 1], "cond", 4) == 0) {
                    ip += 5;
                    if (*dp == 0) {
                        int open_blocks = 1;
                        while (open_blocks > 0 && code[ip] != '\0') {
                            if (code[ip] == '`') {
                                open_blocks--;
                            }
                            ip++;
                        }
                    }
                }
                break;
            case '`':
                break;
        }
        ip++;
    }

    if (file_handle != NULL) {
        fclose(file_handle);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <brainfuck_file>\n", argv[0]);
        return 1;
    }

    char *code = read_file_to_string(argv[1]);
    if (!code) {
        return 1;
    }

    char *processed_code = preprocess_code(code, argv[1]);
    free(code);

    if (!processed_code) {
        return 1;
    }

    interpret(processed_code);
    free(processed_code);

    return 0;
}
