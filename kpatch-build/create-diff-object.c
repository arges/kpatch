/*
 * create-diff-object.c
 *
 * Copyright (C) 2014 Seth Jennings <sjenning@redhat.com>
 * Copyright (C) 2013-2014 Josh Poimboeuf <jpoimboe@redhat.com>
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA,
 * 02110-1301, USA.
 */

#include "kpatch-elf.h"

char *childobj;
enum loglevel loglevel;

struct arguments {
	char *args[4];
	int debug;
};

static char args_doc[] = "original.o patched.o kernel-object output.o";

static struct argp_option options[] = {
	{"debug", 'd', 0, 0, "Show debug output" },
	{ 0 }
};

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	/* Get the input argument from argp_parse, which we
	   know is a pointer to our arguments structure. */
	struct arguments *arguments = state->input;

	switch (key)
	{
		case 'd':
			arguments->debug = 1;
			break;
		case ARGP_KEY_ARG:
			if (state->arg_num >= 4)
				/* Too many arguments. */
				argp_usage (state);
			arguments->args[state->arg_num] = arg;
			break;
		case ARGP_KEY_END:
			if (state->arg_num < 4)
				/* Not enough arguments. */
				argp_usage (state);
			break;
		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static struct argp argp = { options, parse_opt, args_doc, 0 };

int main(int argc, char *argv[])
{
	struct kpatch_elf *kelf_base, *kelf_patched, *kelf_out;
	struct arguments arguments;
	int num_changed, hooks_exist, new_globals_exist;
	struct lookup_table *lookup;
	struct section *sec, *symtab;
	struct symbol *sym;
	char *hint = NULL, *name, *pos;

	arguments.debug = 0;
	argp_parse (&argp, argc, argv, 0, 0, &arguments);
	if (arguments.debug)
		loglevel = DEBUG;

	elf_version(EV_CURRENT);

	childobj = basename(arguments.args[0]);

	kelf_base = kpatch_elf_open(arguments.args[0]);
	kelf_patched = kpatch_elf_open(arguments.args[1]);

	kpatch_compare_elf_headers(kelf_base->elf, kelf_patched->elf);
	kpatch_check_program_headers(kelf_base->elf);
	kpatch_check_program_headers(kelf_patched->elf);

	kpatch_mark_grouped_sections(kelf_patched);
	kpatch_replace_sections_syms(kelf_base);
	kpatch_replace_sections_syms(kelf_patched);
	kpatch_rename_mangled_functions(kelf_base, kelf_patched);

	kpatch_correlate_elfs(kelf_base, kelf_patched);
	kpatch_correlate_static_local_variables(kelf_base, kelf_patched);

	/*
	 * After this point, we don't care about kelf_base anymore.
	 * We access its sections via the twin pointers in the
	 * section, symbol, and rela lists of kelf_patched.
	 */
	kpatch_mark_ignored_sections(kelf_patched);
	kpatch_compare_correlated_elements(kelf_patched);
	kpatch_check_fentry_calls(kelf_patched);
	kpatch_elf_teardown(kelf_base);
	kpatch_elf_free(kelf_base);

	kpatch_mark_ignored_functions_same(kelf_patched);
	kpatch_mark_ignored_sections_same(kelf_patched);

	kpatch_include_standard_elements(kelf_patched);
	num_changed = kpatch_include_changed_functions(kelf_patched);
	kpatch_include_debug_sections(kelf_patched);
	hooks_exist = kpatch_include_hook_elements(kelf_patched);
	kpatch_include_force_elements(kelf_patched);
	new_globals_exist = kpatch_include_new_globals(kelf_patched);

	kpatch_print_changes(kelf_patched);
	kpatch_dump_kelf(kelf_patched);

	kpatch_process_special_sections(kelf_patched);
	kpatch_verify_patchability(kelf_patched);

	if (!num_changed && !new_globals_exist) {
		if (hooks_exist)
			log_debug("no changed functions were found, but hooks exist\n");
		else {
			log_debug("no changed functions were found\n");
			return 3; /* 1 is ERROR, 2 is DIFF_FATAL */
		}
	}

	/* this is destructive to kelf_patched */
	kpatch_migrate_included_elements(kelf_patched, &kelf_out);

	/*
	 * Teardown kelf_patched since we shouldn't access sections or symbols
	 * through it anymore.  Don't free however, since our section and symbol
	 * name fields still point to strings in the Elf object owned by
	 * kpatch_patched.
	 */
	kpatch_elf_teardown(kelf_patched);

	list_for_each_entry(sym, &kelf_out->symbols, list) {
		if (sym->type == STT_FILE) {
			hint = sym->name;
			break;
		}
	}
	if (!hint)
		ERROR("FILE symbol not found in output. Stripped?\n");

	/* create symbol lookup table */
	lookup = lookup_open(arguments.args[2]);

	/* extract module name (destructive to arguments.modulefile) */
	name = basename(arguments.args[2]);
	if (!strncmp(name, "vmlinux-", 8))
		name = "vmlinux";
	else {
		pos = strchr(name,'.');
		if (pos) {
			/* kernel module */
			*pos = '\0';
			pos = name;
			while ((pos = strchr(pos, '-')))
				*pos++ = '_';
		}
	}

	/* create strings, patches, and dynrelas sections */
	kpatch_create_strings_elements(kelf_out);
	kpatch_create_patches_sections(kelf_out, lookup, hint, name);
	kpatch_create_dynamic_rela_sections(kelf_out, lookup, hint, name);
	kpatch_create_hooks_objname_rela(kelf_out, name);
	kpatch_build_strings_section_data(kelf_out);

	kpatch_create_mcount_sections(kelf_out);

	/*
	 *  At this point, the set of output sections and symbols is
	 *  finalized.  Reorder the symbols into linker-compliant
	 *  order and index all the symbols and sections.  After the
	 *  indexes have been established, update index data
	 *  throughout the structure.
	 */
	kpatch_reorder_symbols(kelf_out);
	kpatch_strip_unneeded_syms(kelf_out, lookup);
	kpatch_reindex_elements(kelf_out);

	/*
	 * Update rela section headers and rebuild the rela section data
	 * buffers from the relas lists.
	 */
	symtab = find_section_by_name(&kelf_out->sections, ".symtab");
	list_for_each_entry(sec, &kelf_out->sections, list) {
		if (!is_rela_section(sec))
			continue;
		sec->sh.sh_link = symtab->index;
		sec->sh.sh_info = sec->base->index;
		kpatch_rebuild_rela_section_data(sec);
	}

	kpatch_create_shstrtab(kelf_out);
	kpatch_create_strtab(kelf_out);
	kpatch_create_symtab(kelf_out);
	kpatch_dump_kelf(kelf_out);
	kpatch_write_output_elf(kelf_out, kelf_patched->elf, arguments.args[3]);

	kpatch_elf_free(kelf_patched);
	kpatch_elf_teardown(kelf_out);
	kpatch_elf_free(kelf_out);

	return 0;
}
