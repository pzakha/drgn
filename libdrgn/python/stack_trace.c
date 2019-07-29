// Copyright 2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include "drgnpy.h"
#include "../stack_trace.h"

#define drgn_StackTrace_DOC "TODO"
#define drgn_StackTrace_prog_DOC "TODO"
#define drgn_StackFrame_DOC "TODO"
#define drgn_StackFrame_pc_DOC "TODO"
#define drgn_StackFrame_symbol_DOC "TODO"

static inline Program *StackTrace_prog(StackTrace *trace)
{
	return container_of(trace->trace->prog, Program, prog);
}

static void StackTrace_dealloc(StackTrace *self)
{
	Py_DECREF(StackTrace_prog(self));
	drgn_stack_trace_destroy(self->trace);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *StackTrace_str(StackTrace *self)
{
	struct drgn_error *err;
	PyObject *ret;
	char *str;

	err = drgn_pretty_print_stack_trace(self->trace, &str);
	if (err)
		return set_drgn_error(err);

	ret = PyUnicode_FromString(str);
	free(str);
	return ret;
}

static Py_ssize_t StackTrace_length(StackTrace *self)
{
	return self->trace->num_frames;
}

static StackFrame *StackTrace_item(StackTrace *self, Py_ssize_t i)
{
	struct drgn_stack_frame *frame;
	StackFrame *frame_obj;

	if (i < 0 || !(frame = drgn_stack_trace_frame(self->trace, i))) {
		PyErr_SetString(PyExc_IndexError,
				"stack frame index out of range");
		return NULL;
	}
	frame_obj = (StackFrame *)StackFrame_type.tp_alloc(&StackFrame_type, 0);
	if (!frame_obj)
		return NULL;
	frame_obj->frame = frame;
	frame_obj->trace_obj = self;
	Py_INCREF(self);
	return frame_obj;
}

static Program *StackTrace_get_prog(StackTrace *self, void *arg)
{
	Py_INCREF(StackTrace_prog(self));
	return StackTrace_prog(self);
}

static PySequenceMethods StackTrace_as_sequence = {
	(lenfunc)StackTrace_length,	/* sq_length */
	NULL,				/* sq_concat */
	NULL,				/* sq_repeat */
	(ssizeargfunc)StackTrace_item,	/* sq_item */
};

static PyGetSetDef StackTrace_getset[] = {
	{"prog", (getter)StackTrace_get_prog, NULL, drgn_StackTrace_prog_DOC},
	{},
};

PyTypeObject StackTrace_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"_drgn.StackTrace",			/* tp_name */
	sizeof(StackTrace),			/* tp_basicsize */
	0,					/* tp_itemsize */
	(destructor)StackTrace_dealloc,		/* tp_dealloc */
	NULL,					/* tp_print */
	NULL,					/* tp_getattr */
	NULL,					/* tp_setattr */
	NULL,					/* tp_as_async */
	NULL,					/* tp_repr */
	NULL,					/* tp_as_number */
	&StackTrace_as_sequence,		/* tp_as_sequence */
	NULL,					/* tp_as_mapping */
	NULL,					/* tp_hash  */
	NULL,					/* tp_call */
	(reprfunc)StackTrace_str,		/* tp_str */
	NULL,					/* tp_getattro */
	NULL,					/* tp_setattro */
	NULL,					/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT,			/* tp_flags */
	drgn_StackTrace_DOC,			/* tp_doc */
	NULL,					/* tp_traverse */
	NULL,					/* tp_clear */
	NULL,					/* tp_richcompare */
	0,					/* tp_weaklistoffset */
	NULL,					/* tp_iter */
	NULL,					/* tp_iternext */
	NULL,					/* tp_methods */
	NULL,					/* tp_members */
	StackTrace_getset,			/* tp_getset */
};

static void StackFrame_dealloc(StackFrame *self)
{
	Py_DECREF(self->trace_obj);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *StackFrame_get_pc(StackFrame *self, void *arg)
{
	return PyLong_FromUnsignedLongLong(drgn_stack_frame_pc(self->frame));
}

static Symbol *StackFrame_get_symbol(StackFrame *self, void *arg)
{
	return Program_find_symbol(StackTrace_prog(self->trace_obj),
				   drgn_stack_frame_pc(self->frame));
}

static PyGetSetDef StackFrame_getset[] = {
	{"pc", (getter)StackFrame_get_pc, NULL, drgn_StackFrame_pc_DOC},
	{"symbol", (getter)StackFrame_get_symbol, NULL,
	 drgn_StackFrame_symbol_DOC},
	{},
};

PyTypeObject StackFrame_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"_drgn.StackFrame",			/* tp_name */
	sizeof(StackFrame),			/* tp_basicsize */
	0,					/* tp_itemsize */
	(destructor)StackFrame_dealloc,		/* tp_dealloc */
	NULL,					/* tp_print */
	NULL,					/* tp_getattr */
	NULL,					/* tp_setattr */
	NULL,					/* tp_as_async */
	NULL,					/* tp_repr */
	NULL,					/* tp_as_number */
	NULL,					/* tp_as_sequence */
	NULL,					/* tp_as_mapping */
	NULL,					/* tp_hash  */
	NULL,					/* tp_call */
	NULL,					/* tp_str */ /* TODO? */
	NULL,					/* tp_getattro */
	NULL,					/* tp_setattro */
	NULL,					/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT,			/* tp_flags */
	drgn_StackFrame_DOC,			/* tp_doc */
	NULL,					/* tp_traverse */
	NULL,					/* tp_clear */
	NULL,					/* tp_richcompare */
	0,					/* tp_weaklistoffset */
	NULL,					/* tp_iter */
	NULL,					/* tp_iternext */
	NULL,					/* tp_methods */
	NULL,					/* tp_members */
	StackFrame_getset,			/* tp_getset */
};
