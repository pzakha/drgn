// Copyright 2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#ifndef DRGN_STACK_TRACE_H
#define DRGN_STACK_TRACE_H

#include <stddef.h>
#include <stdint.h>

struct drgn_stack_frame {
	struct drgn_stack_trace *trace;
	uint64_t pc;
	uint64_t regs_set[3];
	uint64_t *regs;
};

struct drgn_stack_trace {
	struct drgn_program *prog;
	size_t num_frames;
	struct drgn_stack_frame frames[];
};

#endif /* DRGN_STACK_TRACE_H */
