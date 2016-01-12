/*
 * livepatch.h - Kernel Live Patching Core (Userspace API)
 *
 * Copyright (C) 2014 Seth Jennings <sjenning@redhat.com>
 * Copyright (C) 2014 SUSE
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _LINUX_LIVEPATCH_H_
#define _LINUX_LIVEPATCH_H_

enum klp_state {
	KLP_DISABLED,
	KLP_ENABLED
};

/**
 * struct klp_func - function structure for live patching
 * @old_name:	name of the function to be patched
 * @new_func:	pointer to the patched function code
 * @old_addr:	a hint conveying at what address the old function
 */
struct klp_func {
	/* external */
	const char *old_name;
	void *new_func;
	/*
	 * The old_addr field is optional and can be used to resolve
	 * duplicate symbol names in the vmlinux object.  If this
	 * information is not present, the symbol is located by name
	 * with kallsyms. If the name is not unique and old_addr is
	 * not provided, the patch application fails as there is no
	 * way to resolve the ambiguity.
	 */
	unsigned long old_addr;

	/* internal */
	unsigned long _pad[11];
};

/**
 * struct klp_reloc - relocation structure for live patching
 * @loc:	address where the relocation will be written
 * @val:	address of the referenced symbol (optional,
 *		vmlinux	patches only)
 * @type:	ELF relocation type
 * @name:	name of the referenced symbol (for lookup/verification)
 * @addend:	offset from the referenced symbol
 * @external:	symbol is either exported or within the live patch module itself
 */
struct klp_reloc {
	unsigned long loc;
	unsigned long val;
	unsigned long type;
	const char *name;
	int addend;
	int external;
};

/**
 * struct klp_object - kernel object structure for live patching
 * @name:	module name (or NULL for vmlinux)
 * @relocs:	relocation entries to be applied at load time
 * @funcs:	function entries for functions to be patched in the object
 */
struct klp_object {
	/* external */
	const char *name;
	struct klp_reloc *relocs;
	struct klp_func *funcs;

	/* internal */
	unsigned long _pad[10];
};

/**
 * struct klp_patch - patch structure for live patching
 * @mod:	reference to the live patch module
 * @objs:	object entries for kernel objects to be patched
 */
struct klp_patch {
	/* external */
	struct module *mod;
	struct klp_object *objs;

	/* internal */
	unsigned long _pad[11];
};

#endif /* _LINUX_LIVEPATCH_H_ */
