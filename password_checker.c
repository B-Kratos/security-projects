// password_checker.c
// Simple password strength checker and local breached-list checker
// Compile: gcc -o password_checker password_checker.c

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define MAXPW 256
#define BREACHED_FILE "breached.txt"

int is_in_breached(const char *pw) {
    FILE *f = fopen(BREACHED_FILE, "r");
    if (!f) return 0; // if file missing, treat as not breached (but print warning)
    char line[MAXPW];
    while (fgets(line, sizeof(line), f)) {
        // remove newline
        line[strcspn(line, "\r\n")] = 0;
        if (strcmp(line, pw) == 0) {
            fclose(f);
            return 1;
        }
    }
    fclose(f);
    return 0;
}

void check_strength(const char *pw) {
    int len = strlen(pw);
    int has_lower=0, has_upper=0, has_digit=0, has_spec=0;
    for (int i=0;i<len;i++) {
        if (islower((unsigned char)pw[i])) has_lower = 1;
        else if (isupper((unsigned char)pw[i])) has_upper = 1;
        else if (isdigit((unsigned char)pw[i])) has_digit = 1;
        else has_spec = 1;
    }

    printf("Password length: %d\n", len);
    printf("Contains lowercase: %s\n", has_lower ? "Yes" : "No");
    printf("Contains uppercase: %s\n", has_upper ? "Yes" : "No");
    printf("Contains digit: %s\n", has_digit ? "Yes" : "No");
    printf("Contains special char: %s\n", has_spec ? "Yes" : "No");

    int score = 0;
    if (len >= 8) score++;
    if (len >= 12) score++;
    if (has_lower && has_upper) score++;
    if (has_digit) score++;
    if (has_spec) score++;

    if (score <= 1) printf("Strength: Very weak\n");
    else if (score == 2) printf("Strength: Weak\n");
    else if (score == 3) printf("Strength: Medium\n");
    else if (score >= 4) printf("Strength: Strong\n");
}

int main(int argc, char *argv[]) {
    char pw[MAXPW];
    if (argc >= 2) {
        strncpy(pw, argv[1], MAXPW-1);
        pw[MAXPW-1] = 0;
    } else {
        printf("Enter password (visible input): ");
        if (!fgets(pw, sizeof(pw), stdin)) return 1;
        pw[strcspn(pw, "\r\n")] = 0;
    }

    if (strlen(pw) == 0) {
        printf("No password entered. Exiting.\n");
        return 1;
    }

    // Basic checks
    check_strength(pw);

    // Breached list
    if (is_in_breached(pw)) {
        printf("WARNING: This password appears in the local breached list (breached.txt).\n");
    } else {
        printf("This password was NOT found in the local breached list.\n");
    }

    printf("\nAdvice: use a long passphrase (>=12 chars), mix letters, digits, and symbols, and avoid common words.\n");
    return 0;
}
