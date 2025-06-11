#ifndef __EBPF_READ_H__
#define __EBPF_READ_H__

#define TEST_SAMLL_SIZE 10

// #define MAX_DATA_SIZE  4096    // 4KB
#define MAX_DATA_SIZE  TEST_SAMLL_SIZE
#define MAX_READ_SIZE  131072  // 128KB
#define MAX_WRITE_SIZE 131072
#define MAX_LOOP_COUNT 32

typedef struct read_data_key {
	uint64_t file_handle;
    uint64_t offset;  // 需 MAX_DATA_SIZE 对齐
} read_data_key_t;

typedef struct read_data_value {
    uint32_t size;
    char     data[MAX_DATA_SIZE];
} read_data_value_t;

#undef MAX_ENTRIES
#define MAX_ENTRIES (2 << 16)

#endif