// Copyright 2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include "internal.h"
#include "platform.h"

static struct drgn_error *
linux_kernel_set_initial_registers_x86_64(Dwfl_Thread *thread,
					  struct drgn_object *task_obj)
{
	struct drgn_error *err;
	struct drgn_program *prog = task_obj->prog;
	struct drgn_object frame_obj, reg_obj;
	struct drgn_qualified_type frame_type;
	Dwarf_Word dwarf_regs[17];
	uint64_t reg;

	drgn_object_init(&frame_obj, prog);
	drgn_object_init(&reg_obj, prog);

	/* TODO: I think this changed in some kernel version. */
	err = drgn_object_member_dereference(&frame_obj, task_obj, "thread");
	if (err)
		goto out;
	err = drgn_object_member(&frame_obj, &frame_obj, "sp");
	if (err)
		goto out;
	err = drgn_program_find_type(prog, "struct inactive_task_frame *", NULL,
				     &frame_type);
	if (err)
		goto out;
	err = drgn_object_cast(&frame_obj, frame_type, &frame_obj);
	if (err)
		goto out;

	dwarf_regs[0] = 0; /* rax */
	dwarf_regs[1] = 0; /* rdx */
	dwarf_regs[2] = 0; /* rcx */
	dwarf_regs[3] = 0; /* rbx */
	dwarf_regs[4] = 0; /* rsi */
	dwarf_regs[5] = 0; /* rdi */
	err = drgn_object_member_dereference(&reg_obj, &frame_obj, "bp");
	if (err)
		goto out;
	err = drgn_object_read_unsigned(&reg_obj, &reg);
	if (err)
		goto out;
	dwarf_regs[6] = reg;
	err = drgn_object_read_unsigned(&frame_obj, &reg);
	if (err)
		goto out;
	dwarf_regs[7] = reg; /* rsp */
	dwarf_regs[8] = 0; /* r8 */
	dwarf_regs[9] = 0; /* r9 */
	dwarf_regs[10] = 0; /* r10 */
	dwarf_regs[11] = 0; /* r11 */
	err = drgn_object_member_dereference(&reg_obj, &frame_obj, "r12");
	if (err)
		goto out;
	err = drgn_object_read_unsigned(&reg_obj, &reg);
	if (err)
		goto out;
	dwarf_regs[12] = reg;
	err = drgn_object_member_dereference(&reg_obj, &frame_obj, "r13");
	if (err)
		goto out;
	err = drgn_object_read_unsigned(&reg_obj, &reg);
	if (err)
		goto out;
	dwarf_regs[13] = reg;
	err = drgn_object_member_dereference(&reg_obj, &frame_obj, "r14");
	if (err)
		goto out;
	err = drgn_object_read_unsigned(&reg_obj, &reg);
	if (err)
		goto out;
	dwarf_regs[14] = reg;
	err = drgn_object_member_dereference(&reg_obj, &frame_obj, "r15");
	if (err)
		goto out;
	err = drgn_object_read_unsigned(&reg_obj, &reg);
	if (err)
		goto out;
	dwarf_regs[15] = reg;
	err = drgn_object_member_dereference(&reg_obj, &frame_obj, "ret_addr");
	if (err)
		goto out;
	err = drgn_object_read_unsigned(&reg_obj, &reg);
	if (err)
		goto out;
	dwarf_regs[16] = reg;

	/* TODO: ignore the unknown registers */
	if (!dwfl_thread_state_registers(thread, 0, 17, dwarf_regs))
		err = drgn_error_libdwfl();

out:
	drgn_object_deinit(&reg_obj);
	drgn_object_deinit(&frame_obj);
	return err;
}

const struct drgn_architecture_info arch_info_x86_64 = {
	.name = "x86-64",
	.arch = DRGN_ARCH_X86_64,
	.default_flags = (DRGN_PLATFORM_IS_64_BIT |
			  DRGN_PLATFORM_IS_LITTLE_ENDIAN),
	.linux_kernel_set_initial_registers = linux_kernel_set_initial_registers_x86_64,
};
