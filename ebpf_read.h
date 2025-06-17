#ifndef __EBPF_READ_H__
#define __EBPF_READ_H__

#define TEST_SAMLL_SIZE 10

#define DATA_MAX_BLOCK_SIZE  4096    // 4KB
// #define DATA_MAX_BLOCK_SIZE  TEST_SAMLL_SIZE
#define MAX_READ_SIZE  131072  // 128KB
#define MAX_WRITE_SIZE 131072
#define MAX_LOOP_COUNT 32

typedef struct read_data_key {
	uint64_t file_handle;
    uint64_t offset;  // 需 DATA_MAX_BLOCK_SIZE 对齐
} read_data_key_t;

typedef struct read_data_value {
    uint32_t size;
    uint8_t  is_last;     // 标记是否为最后一块（1 表示是，0 表示否）
    char     data[DATA_MAX_BLOCK_SIZE];
} read_data_value_t;

struct efuse_read_in {
	uint64_t fh;    // file handle
	uint64_t offset; // offset to read from
	uint64_t size;   // size of data to read
};

struct efuse_cache_in {
	uint64_t copied;
	uint64_t data_offset;
	uint64_t copy_len;
	read_data_value_t *data; // 缓存数据
};

#define TEST_CNT   10     // 探测阶段请求数
#define ROUND_CNT  5000   // 每轮总请求数

typedef struct read_stat {
    uint64_t cache_time_sum;
    uint64_t passthrough_time_sum;
    uint32_t cache_cnt;
    uint32_t passthrough_cnt;
    uint32_t total_cnt;
    uint8_t  prefer_cache;
} read_stat_t;

#undef MAX_ENTRIES
#define MAX_ENTRIES (2 << 16)

#endif