#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s <input_file>\n", argv[0]);
        return 1;
    }
    
    FILE* f = fopen(argv[1], "rb");
    if (!f) {
        printf("Cannot open file\n");
        return 1;
    }
    
    char buffer[256];
    size_t bytes_read = fread(buffer, 1, sizeof(buffer), f);
    fclose(f);
    
    printf("Read %zu bytes (safe)\n", bytes_read);
    return 0;
}
