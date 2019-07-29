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
drgn_stack_frame_register(struct drgn_stack_frame *frame,
			  const char *name, uint64_t *ret)
{
	/* XXX: this is architecture-specific. */
	static const char * const names[] = {
		"rax",
		"rdx",
		"rcx",
		"rbx",
		"rsi",
		"rdi",
		"rbp",
		"rsp",
		"r8",
		"r9",
		"r10",
		"r11",
		"r12",
		"r13",
		"r14",
		"r15",
		"ret_addr",
	};
	size_t i;

	if (strcmp(name, "rip") == 0) {
		*ret = frame->pc;
		return NULL;
	}
	for (i = 0; i < ARRAY_SIZE(names); i++) {
		if (strcmp(name, names[i]) == 0) {
			if (frame->regs_set[i / 64] & (1 << (i % 64))) {
				*ret = frame->regs[i];
				return NULL;
			} else {
				return drgn_error_format(DRGN_ERROR_OTHER,
							 "%s value is not known at 0x%" PRIx64,
							 name, frame->pc);
			}
		}
	}
	return drgn_error_format(DRGN_ERROR_OTHER, "no register named %s",
				 name);
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

/*
 * XXX: this is awful, but libdwfl doesn't have a supported way to get at the
 * registers.
 */
struct Dwfl_Frame
{
  Dwfl_Thread *thread;
  /* Previous (outer) frame.  */
  Dwfl_Frame *unwound;
  bool signal_frame : 1;
  bool initial_frame : 1;
  enum
  {
    /* This structure is still being initialized or there was an error
       initializing it.  */
    DWFL_FRAME_STATE_ERROR,
    /* PC field is valid.  */
    DWFL_FRAME_STATE_PC_SET,
    /* PC field is undefined, this means the next (inner) frame was the
       outermost frame.  */
    DWFL_FRAME_STATE_PC_UNDEFINED
  } pc_state;
  /* Either initialized from appropriate REGS element or on some archs
     initialized separately as the return address has no DWARF register.  */
  Dwarf_Addr pc;
  /* (1 << X) bitmask where 0 <= X < ebl_frame_nregs.  */
  uint64_t regs_set[3];
  /* REGS array size is ebl_frame_nregs.
     REGS_SET tells which of the REGS are valid.  */
  Dwarf_Addr regs[];
};

static int drgn_append_stack_frame(Dwfl_Frame *dwfl_frame, void *_arg)
{
	struct drgn_error *err;
	struct drgn_append_stack_frame_arg *arg = _arg;
	struct drgn_stack_trace *trace = arg->trace;
	struct drgn_program *prog = trace->prog;
	size_t i, j, num_regs;
	Dwarf_Addr pc;
	uint64_t *regs;
	struct drgn_stack_frame *frame;

	if (!dwfl_frame_pc(dwfl_frame, &pc, NULL)) {
		err = drgn_error_libdwfl();
		goto err;
	}
	num_regs = 0;
	for (i = 0; i < 3; i++) {
		for (j = 0; j < 64; j++) {
			/* XXX */
			if (dwfl_frame->regs_set[i] & (1 << j))
				num_regs = 64 * i + j;
		}
	}
	regs = malloc_array(num_regs, sizeof(*regs));
	if (!regs) {
		err = &drgn_enomem;
		goto err;
	}

	if (trace->num_frames >= arg->capacity) {
		size_t new_capacity, bytes;

		if (__builtin_mul_overflow(2U, arg->capacity, &new_capacity) ||
		    __builtin_mul_overflow(new_capacity,
					   sizeof(trace->frames[0]), &bytes) ||
		    __builtin_add_overflow(bytes, sizeof(*trace), &bytes) ||
		    !(trace = realloc(trace, bytes))) {
			free(regs);
			err = &drgn_enomem;
			goto err;
		}
		arg->trace = trace;
		arg->capacity = new_capacity;
	}
	frame = &trace->frames[trace->num_frames++];
	frame->pc = pc;
	memcpy(frame->regs_set, dwfl_frame->regs_set, sizeof(frame->regs_set));
	memcpy(regs, dwfl_frame->regs, num_regs * sizeof(*regs));
	frame->regs = regs;
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
