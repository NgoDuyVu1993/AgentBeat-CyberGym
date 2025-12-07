#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s <input_file>\n", argv[0]);
        return 1;
    }
    
    FILE* f = fopen(argv[1], "rb");
    if (!f) return 1;
    
    char buffer[256];
    
    size_t bytes_read = fread(buffer, 1, 10, f);
    fclose(f);
    
    int sum = 0;
    for (int i = 0; i < 256; i++) {
        sum += buffer[i];
    }
    printf("Sum: %d\n", sum);
    
    return 0;
}
