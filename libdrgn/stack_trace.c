// Copyright 2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include <elfutils/libdwfl.h>
#include <endian.h>
#include <inttypes.h>
#include <stdlib.h>

#include "internal.h"
#include "program.h"
#include "stack_trace.h"
#include "string_builder.h"
#include "symbol.h"

LIBDRGN_PUBLIC void drgn_stack_trace_destroy(struct drgn_stack_trace *trace)
{
	free(trace);
}

LIBDRGN_PUBLIC
size_t drgn_stack_trace_num_frames(struct drgn_stack_trace *trace)
{
	return trace->num_frames;
}

LIBDRGN_PUBLIC struct drgn_stack_frame *
drgn_stack_trace_frame(struct drgn_stack_trace *trace, size_t i)
{
	if (i >= trace->num_frames)
		return NULL;
	return &trace->frames[i];
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_pretty_print_stack_trace(struct drgn_stack_trace *trace, char **ret)
{
	struct drgn_error *err;
	/* TODO: figure out this format. */
	struct string_builder str = {};
	size_t i;

	for (i = 0; i < trace->num_frames; i++) {
		struct drgn_stack_frame *frame = &trace->frames[i];
		uint64_t pc;
		struct drgn_symbol sym;

		pc = drgn_stack_frame_pc(frame);
		err = drgn_program_find_symbol_internal(trace->prog, pc, &sym);
		if (err && err != &drgn_not_found)
			goto err;
		if (!string_builder_appendf(&str, "#%zu ", i)) {
			err = &drgn_enomem;
			goto err;
		}
		if (err) {
			if (!string_builder_appendf(&str, "0x%" PRIx64, pc)) {
				err = &drgn_enomem;
				goto err;
			}
		} else {
			if (!string_builder_appendf(&str,
						    "0x%" PRIx64 " %s+0x%" PRIx64 "/0x%" PRIx64,
						    pc, sym.name,
						    pc - sym.address, sym.size)) {
				err = &drgn_enomem;
				goto err;
			}
		}
		if (i != trace->num_frames - 1 &&
		    !string_builder_appendc(&str, '\n')) {
			err = &drgn_enomem;
			goto err;
		}
	}
	if (!string_builder_finalize(&str, ret)) {
		err = &drgn_enomem;
		goto err;
	}
	return NULL;

err:
	free(str.str);
	return err;
}

LIBDRGN_PUBLIC uint64_t drgn_stack_frame_pc(struct drgn_stack_frame *frame)
{
	return frame->pc;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_stack_frame_symbol(struct drgn_stack_frame *frame,
			struct drgn_symbol **ret)
{
	return drgn_program_find_symbol(frame->trace->prog, frame->pc, ret);
}

static bool drgn_thread_memory_read(Dwfl *dwfl, Dwarf_Addr addr,
				    Dwarf_Word *result, void *dwfl_arg)
{
	struct drgn_error *err;
	struct drgn_program *prog = dwfl_arg;
	bool is_little_endian = drgn_program_is_little_endian(prog);

	if (drgn_program_is_64_bit(prog)) {
		uint64_t u64;

		err = drgn_program_read_memory(prog, &u64, addr, sizeof(u64),
					       false);
		if (err)
			goto err;
		*result = is_little_endian ? le64toh(u64) : be64toh(u64);
	} else {
		uint32_t u32;

		err = drgn_program_read_memory(prog, &u32, addr, sizeof(u32),
					       false);
		if (err)
			goto err;
		*result = is_little_endian ? le32toh(u32) : be32toh(u32);
	}
	return true;

err:
	drgn_error_destroy(prog->stack_trace_err);
	prog->stack_trace_err = err;
	return false;
}

static pid_t drgn_linux_kernel_next_thread(Dwfl *dwfl, void *dwfl_arg,
					   void **thread_argp)
{
	struct drgn_program *prog = dwfl_arg;

	if (*thread_argp || !prog->stack_trace_obj)
		return 0;
	*thread_argp = (void *)prog->stack_trace_obj;
	return 1;
}

static bool drgn_linux_kernel_set_initial_registers(Dwfl_Thread *thread,
						    void *thread_arg)
{
	struct drgn_error *err;
	struct drgn_object *task_obj = thread_arg;
	struct drgn_program *prog = task_obj->prog;

	err = prog->platform.arch->linux_kernel_set_initial_registers(thread,
								      task_obj);
	if (err) {
		drgn_error_destroy(prog->stack_trace_err);
		prog->stack_trace_err = err;
		return false;
	}
	return true;
}

struct drgn_append_stack_frame_arg {
	struct drgn_stack_trace *trace;
	size_t capacity;
};

static int drgn_append_stack_frame(Dwfl_Frame *frame, void *_arg)
{
	struct drgn_error *err;
	struct drgn_append_stack_frame_arg *arg = _arg;
	struct drgn_stack_trace *trace = arg->trace;
	struct drgn_program *prog = trace->prog;
	Dwarf_Addr pc;

	if (!dwfl_frame_pc(frame, &pc, NULL)) {
		err = drgn_error_libdwfl();
		goto err;
	}

	if (trace->num_frames >= arg->capacity) {
		size_t new_capacity, bytes;

		if (__builtin_mul_overflow(2U, arg->capacity, &new_capacity) ||
		    __builtin_mul_overflow(new_capacity,
					   sizeof(trace->frames[0]), &bytes) ||
		    __builtin_add_overflow(bytes, sizeof(*trace), &bytes) ||
		    !(trace = realloc(trace, bytes))) {
			err = &drgn_enomem;
			goto err;
		}
		arg->trace = trace;
		arg->capacity = new_capacity;
	}
	trace->frames[trace->num_frames++].pc = pc;
	return DWARF_CB_OK;

err:
	drgn_error_destroy(prog->stack_trace_err);
	prog->stack_trace_err = err;
	return DWARF_CB_ABORT;
}

static const Dwfl_Thread_Callbacks drgn_linux_kernel_thread_callbacks = {
	.next_thread = drgn_linux_kernel_next_thread,
	.memory_read = drgn_thread_memory_read,
	.set_initial_registers = drgn_linux_kernel_set_initial_registers,
};

struct drgn_error *drgn_object_stack_trace(const struct drgn_object *obj,
					   struct drgn_stack_trace **ret)
{
	struct drgn_error *err;
	struct drgn_program *prog = obj->prog;
	Dwfl *dwfl;
	struct drgn_append_stack_frame_arg append_arg;
	struct drgn_stack_trace *trace;
	int dwfl_ret;
	size_t i;

	if (!prog->has_platform) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "cannot unwind stack without platform");
	}
	if (!(prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL)) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "stack unwinding is currently only supported for the Linux kernel");
	}
	if (!prog->platform.arch->linux_kernel_set_initial_registers) {
		return drgn_error_format(DRGN_ERROR_INVALID_ARGUMENT,
					 "stack unwinding is not supported for %s architecture",
					 prog->platform.arch->name);
	}

	err = drgn_program_get_dwfl(prog, &dwfl);
	if (err)
		return err;
	if (!prog->attached_dwfl_state) {
		if (!dwfl_attach_state(dwfl, NULL, 0,
				       &drgn_linux_kernel_thread_callbacks,
				       prog))
			return drgn_error_libdwfl();
		prog->attached_dwfl_state = true;
	}

	append_arg.trace = malloc(sizeof(*append_arg.trace) +
				  sizeof(append_arg.trace->frames[0]));
	if (!append_arg.trace)
		return &drgn_enomem;
	append_arg.trace->prog = prog;
	append_arg.trace->num_frames = 0;
	append_arg.capacity = 1;

	prog->stack_trace_obj = obj;
	dwfl_ret = dwfl_getthread_frames(dwfl, 1, drgn_append_stack_frame,
					 &append_arg);
	prog->stack_trace_obj = NULL;
	if (prog->stack_trace_err) {
		err = prog->stack_trace_err;
		prog->stack_trace_err = NULL;
		if (dwfl_ret)
			goto err;
		/* We had an error but libdwfl was able to continue. */
		drgn_error_destroy(err);
	} else if (dwfl_ret && !append_arg.trace->num_frames) {
		/* libdwfl had an error TODO. */
		err = drgn_error_libdwfl();
		goto err;
	}

	/* Shrink the trace to fit if we can, but don't fail if we can't. */
	trace = realloc(append_arg.trace,
			sizeof(*append_arg.trace) +
			append_arg.trace->num_frames *
			sizeof(append_arg.trace->frames[0]));
	if (!trace)
		trace = append_arg.trace;
	for (i = 0; i < trace->num_frames; i++)
		trace->frames[i].trace = trace;
	*ret = trace;
	return NULL;

err:
	free(append_arg.trace);
	return err;
}
