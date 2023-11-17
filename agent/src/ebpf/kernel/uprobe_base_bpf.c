/*
 * Copyright (c) 2022 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define HASH_ENTRIES_MAX 40960

/*
 * The binary executable file offset of the GO process
 * key: pid
 * value: struct member_offsets
 */
// struct {
// 	__uint(type, BPF_MAP_TYPE_HASH);
// 	__type(key, int);
// 	__type(value, struct member_offsets);
// 	__uint(max_entries, HASH_ENTRIES_MAX);
// } uprobe_offsets_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct member_offsets);
	__uint(max_entries, 1);
} uprobe_offsets_map_mocked SEC(".maps");
// int uprobe_offsets_map_set = 0;


/*
 * Goroutines Map
 * key: {tgid, pid}
 * value: goroutine ID
 */
// struct {
// 	__uint(type, BPF_MAP_TYPE_HASH);
// 	__type(key, __u64);
// 	__type(value, __s64);
// 	__uint(max_entries, MAX_SYSTEM_THREADS);
// } goroutines_map SEC(".maps");

#define MAX_ENTRIES 229
#define KEY_SIZE_goroutines_map 8
#define VALUE_SIZE_goroutines_map 8
struct map_entry_goroutines_map {
	char used;
	char key[KEY_SIZE_goroutines_map];
	char value[VALUE_SIZE_goroutines_map];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, unsigned int);
	__type(value, struct map_entry_goroutines_map);
} goroutines_map_mocked_hash SEC(".maps");


static inline int map_hash(const char *buf, int sz)
{
	int val = 5381;
	for (int i = 0; i < sz; i++) {
		val = ((val << 5) + val) ^ (int)buf[i];
	}
	return val;
}

static inline int map_inner_lookup_goroutines_map(const char *buf, unsigned *hash_out)
{
	unsigned hash = map_hash(buf, KEY_SIZE_goroutines_map);
	if (hash_out)
		*hash_out = hash;
	int slot = hash % MAX_ENTRIES;
	for (unsigned i = slot, j = 0; j < MAX_ENTRIES;
	     i = (i + 1) % MAX_ENTRIES, j++) {
		struct map_entry_goroutines_map *ent =
			(struct map_entry_goroutines_map *)bpf_map_lookup_elem(&goroutines_map_mocked_hash, &i);
		if (ent && ent->used) {
			int matched = true;
			for (int k = 0; k < KEY_SIZE_goroutines_map; k++) {
				if (buf[k] != ent->key[k]) {
					matched = false;
					break;
				}
			}
			if (matched)
				return i;
		}
	}
	return -1;
}

static __always_inline int map_update_goroutines_map(const char *key, const char *value)
{
	unsigned hash_val;
	int id = map_inner_lookup_goroutines_map(key, &hash_val);
	if (id != -1) {
		struct map_entry_goroutines_map *ent =
			(struct map_entry_goroutines_map *)bpf_map_lookup_elem(&goroutines_map_mocked_hash, &id);
		if (ent) {
			for (int i = 0; i < VALUE_SIZE_goroutines_map; i++)
				ent->value[i] = value[i];
		}
		return 0;
	} else {
		int slot = hash_val % MAX_ENTRIES;
		for (unsigned i = slot, j = 0; j < MAX_ENTRIES;
		     i = (i + 1) % MAX_ENTRIES, j++) {
			struct map_entry_goroutines_map *ent =
				(struct map_entry_goroutines_map *)bpf_map_lookup_elem(
					&goroutines_map_mocked_hash, &i);
			if (ent && !ent->used) {
				ent->used = 1;
				for (int k = 0; k < KEY_SIZE_goroutines_map; k++)
					ent->key[k] = key[k];
				for (int k = 0; k < VALUE_SIZE_goroutines_map; k++)
					ent->value[k] = value[k];
				return 0;
			}
		}
		return -1;
	}
	return 0;
}
static __always_inline void *map_lookup_goroutines_map(const char *key)
{
	int id = map_inner_lookup_goroutines_map(key, NULL);
	if (id == -1)
		return NULL;
	struct map_entry_goroutines_map *ent =
		(struct map_entry_goroutines_map *)bpf_map_lookup_elem(&goroutines_map_mocked_hash, &id);
	if (ent) {
		return ent->value;
	} else
		return NULL;
}
static __always_inline int map_remove_goroutines_map(const char *key)
{
	int id = map_inner_lookup_goroutines_map(key, NULL);
	if (id == -1)
		return -1;
	struct map_entry_goroutines_map *ent =
		(struct map_entry_goroutines_map *)bpf_map_lookup_elem(&goroutines_map_mocked_hash, &id);
	if (ent) {
		ent->used = 0;
		return 0;
	} else
		return -1;
}

static __inline int get_uprobe_offset(int offset_idx)
{
	__u64 id;
	pid_t pid;

	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	struct member_offsets *offsets;
	__u32 key = 0;
	offsets = bpf_map_lookup_elem(&uprobe_offsets_map_mocked, &key);
	if (offsets) {
		return offsets->data[offset_idx];
	}

	return -1;
}

static __inline __u32 get_go_version(void)
{
	__u64 id;
	pid_t pid;

	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	struct member_offsets *offsets;
	__u32 key = 0;
	offsets = bpf_map_lookup_elem(&uprobe_offsets_map_mocked, &key);
	if (offsets) {
		return offsets->version;
	}

	return 0;
}

static __inline int get_runtime_g_goid_offset(void)
{
	return get_uprobe_offset(runtime_g_goid_offset);
}

static __inline int get_crypto_tls_conn_conn_offset(void)
{
	return get_uprobe_offset(crypto_tls_conn_conn_offset);
}

static __inline int get_net_poll_fd_sysfd(void)
{
	return get_uprobe_offset(net_poll_fd_sysfd);
}

static __inline __s64 get_current_goroutine(void)
{
	  __u64 current_thread = bpf_get_current_pid_tgid();
	//   __s64 *goid_ptr = bpf_map_lookup_elem(&goroutines_map, &current_thread);
	__s64 * goid_ptr=map_lookup_goroutines_map((const char*)&current_thread);
	if(goid_ptr !=NULL) {
		return *goid_ptr;
	}
	return 0;
}

SEC("uprobe/runtime.casgstatus")
int runtime_casgstatus(struct pt_regs *ctx)
{
	int offset_g_goid = get_runtime_g_goid_offset();
	if (offset_g_goid < 0) {
		return 0;
	}

	__s32 newval;
	void *g_ptr;

	if (get_go_version() >= GO_VERSION(1, 17, 0)) {
		g_ptr = (void *)(ctx->rax);
		newval = (__s32)(ctx->rcx);
	} else {
		bpf_probe_read(&g_ptr, sizeof(g_ptr), (void *)(ctx->rsp + 8));
		bpf_probe_read(&newval, sizeof(newval),
				   (void *)(ctx->rsp + 20));
	}

	if (newval != 2) {
		return 0;
	}

	__s64 goid = 0;
	bpf_probe_read(&goid, sizeof(goid), g_ptr + offset_g_goid);
	__u64 current_thread = bpf_get_current_pid_tgid();
	//   bpf_map_update_elem(&goroutines_map, &current_thread, &goid, BPF_ANY);
	map_update_goroutines_map((const char*)&current_thread, (const char*)&goid);
	return 0;
}

// /sys/kernel/debug/tracing/events/sched/sched_process_exit/format
SEC("tracepoint/sched/sched_process_exit")
int bpf_func_sched_process_exit(struct sched_comm_exit_ctx *ctx)
{
	pid_t pid, tid;
	__u64 id;

	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	tid = (__u32)id;

	// If is a process, clear uprobe_offsets_map element and submit event.
	if (pid == tid) {
		// bpf_map_delete_elem(&uprobe_offsets_map, &pid);
		// __atomic_store_n(&uprobe_offsets_map_set, 0, __ATOMIC_RELEASE);
		struct process_event_t data;
		data.pid = pid;
		data.meta.event_type = EVENT_TYPE_PROC_EXIT;
		bpf_get_current_comm(data.name, sizeof(data.name));
		int ret = bpf_perf_event_output(ctx, &NAME(socket_data),
						BPF_F_CURRENT_CPU, &data,
						sizeof(data));

		if (ret) {
			bpf_debug
				("bpf_func_sched_process_exit event outputfaild: %d\n",
				 ret);
		}

	}

	//   bpf_map_delete_elem(&goroutines_map, &id);
	map_remove_goroutines_map((const char*)&id);
	return 0;
}

// /sys/kernel/debug/tracing/events/sched/sched_process_exec/format
SEC("tracepoint/sched/sched_process_exec")
int bpf_func_sched_process_exec(struct sched_comm_exec_ctx *ctx)
{
	struct process_event_t data;
	__u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;
	pid_t tid = (__u32) id;

	if (pid == tid) {
		data.meta.event_type = EVENT_TYPE_PROC_EXEC;
		data.pid = pid;
		bpf_get_current_comm(data.name, sizeof(data.name));
		int ret = bpf_perf_event_output(ctx, &NAME(socket_data),
						BPF_F_CURRENT_CPU, &data,
						sizeof(data));

		if (ret) {
			bpf_debug
				("bpf_func_sys_exit_execve event output() faild: %d\n",
				 ret);
		}
	}

	return 0;
}
