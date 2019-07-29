// Copyright 2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#ifndef DRGN_PLATFORM_H
#define DRGN_PLATFORM_H

#include <elfutils/libdwfl.h>

#include "drgn.h"

struct drgn_architecture_info {
	const char *name;
	enum drgn_architecture arch;
	enum drgn_platform_flags default_flags;
	struct drgn_error *(*linux_kernel_set_initial_registers)(Dwfl_Thread *,
								 struct drgn_object *);
};

extern const struct drgn_architecture_info arch_info_x86_64;

struct drgn_platform {
	const struct drgn_architecture_info *arch;
	enum drgn_platform_flags flags;
};

void drgn_platform_from_elf(GElf_Ehdr *ehdr, struct drgn_platform *ret);

#endif /* DRGN_PLATFORM_H */
