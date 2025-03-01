// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * @file
 *
 * Stack trace internals
 *
 * See @ref StackTraceInternals.
 */

#ifndef DRGN_STACK_TRACE_H
#define DRGN_STACK_TRACE_H

#include <stddef.h>

/**
 * @ingroup Internals
 *
 * @defgroup StackTraceInternals Stack traces
 *
 * Stack trace internals.
 *
 * This provides the internal data structures used for stack traces.
 *
 * @{
 */

struct drgn_stack_frame {
	struct drgn_register_state *regs;
};

struct drgn_stack_trace {
	struct drgn_program *prog;
	size_t num_frames;
	struct drgn_stack_frame frames[];
};

/** @} */

#endif /* DRGN_STACK_TRACE_H */
