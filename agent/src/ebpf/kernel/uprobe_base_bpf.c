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

__s64 goroutines_map_mocked = -1;

struct spin_lock_container {
	struct bpf_spin_lock lock;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct spin_lock_container);
	__uint(max_entries, 1);
} goroutines_map_lock SEC(".maps");

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
	//   __u64 current_thread = bpf_get_current_pid_tgid();
	//   __s64 *goid_ptr = bpf_map_lookup_elem(&goroutines_map, &current_thread);
	// __u32 key = 0;
	// struct spin_lock_container *lock =
	// 	bpf_map_lookup_elem(&goroutines_map_lock, &key);
	// if (!lock)
	// 	return 0;
	// bpf_spin_lock(&lock->lock);
	__s64 goid = goroutines_map_mocked;
	// bpf_spin_unlock(&lock->lock);
	if (goid != -1) {
		return goid;
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
	// __u32 key = 0;
	// struct spin_lock_container *lock =
	// bpf_map_lookup_elem(&goroutines_map_lock, &key);
	// if (!lock)
	// 	return 0;
	// bpf_spin_lock(&lock->lock);
	goroutines_map_mocked = goid;
	// bpf_spin_unlock(&lock->lock);
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
	// __u32 key = 0;
	// struct spin_lock_container *lock =
	// bpf_map_lookup_elem(&goroutines_map_lock, &key);
	// if (!lock)
	// 	return 0;
	// bpf_spin_lock(&lock->lock);
	goroutines_map_mocked = -1;
	// bpf_spin_unlock(&lock->lock);
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
