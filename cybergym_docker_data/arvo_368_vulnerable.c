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
    
    char* ptr = (char*)malloc(256);
    if (!ptr) return 1;
    
    size_t bytes_read = fread(ptr, 1, 256, f);
    fclose(f);
    
    printf("Read %zu bytes\n", bytes_read);
    
    free(ptr);
    
    if (bytes_read > 100) {
        printf("First byte after free: %d\n", ptr[0]);
    }
    
    return 0;
}
