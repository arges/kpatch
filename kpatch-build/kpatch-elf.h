/*
 * kpatch-elf.h
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <error.h>
#include <gelf.h>
#include <argp.h>
#include <libgen.h>
#include <unistd.h>

#include "list.h"
#include "lookup.h"
#include "asm/insn.h"
#include "kpatch-patch.h"

extern char *childobj;

#define ERROR(format, ...) \
	error(1, 0, "ERROR: %s: %s: %d: " format, childobj, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define DIFF_FATAL(format, ...) \
({ \
	fprintf(stderr, "ERROR: %s: " format "\n", childobj, ##__VA_ARGS__); \
	error(2, 0, "unreconcilable difference"); \
})

#define log_debug(format, ...) log(DEBUG, format, ##__VA_ARGS__)
#define log_normal(format, ...) log(NORMAL, "%s: " format, childobj, ##__VA_ARGS__)

#define log(level, format, ...) \
({ \
	if (loglevel <= (level)) \
		printf(format, ##__VA_ARGS__); \
})

enum loglevel {
	DEBUG,
	NORMAL
};

extern enum loglevel loglevel;

/*******************
 * Data structures
 * ****************/
struct section;
struct symbol;
struct rela;

enum status {
	NEW,
	CHANGED,
	SAME
};

struct section {
	struct list_head list;
	struct section *twin;
	GElf_Shdr sh;
	Elf_Data *data;
	char *name;
	int index;
	enum status status;
	int include;
	int ignore;
	int grouped;
	union {
		struct { /* if (is_rela_section()) */
			struct section *base;
			struct list_head relas;
		};
		struct { /* else */
			struct section *rela;
			struct symbol *secsym, *sym;
		};
	};
};

struct symbol {
	struct list_head list;
	struct symbol *twin;
	struct section *sec;
	GElf_Sym sym;
	char *name;
	int index;
	unsigned char bind, type;
	enum status status;
	union {
		int include; /* used in the patched elf */
		int strip; /* used in the output elf */
	};
	int has_fentry_call;
};

struct rela {
	struct list_head list;
	GElf_Rela rela;
	struct symbol *sym;
	unsigned int type;
	int addend;
	int offset;
	char *string;
};

struct string {
	struct list_head list;
	char *name;
};

struct kpatch_elf {
	Elf *elf;
	struct list_head sections;
	struct list_head symbols;
	struct list_head strings;
	int fd;
};

struct special_section {
	char *name;
	int (*group_size)(struct kpatch_elf *kelf, int offset);
};

/**********************
 * Function Prototypes
 *********************/

struct kpatch_elf *kpatch_elf_open(const char *name);
void kpatch_compare_elf_headers(Elf *elf1, Elf *elf2);
void kpatch_check_program_headers(Elf *elf);

void kpatch_strip_unused_switch_syms(struct kpatch_elf *kelf);

void kpatch_mark_grouped_sections(struct kpatch_elf *kelf);
void kpatch_replace_sections_syms(struct kpatch_elf *kelf);
void kpatch_rename_mangled_functions(struct kpatch_elf *base,
				     struct kpatch_elf *patched);
void kpatch_correlate_elfs(struct kpatch_elf *kelf1, struct kpatch_elf *kelf2);
void kpatch_correlate_static_local_variables(struct kpatch_elf *base,
					     struct kpatch_elf *patched);
void kpatch_mark_ignored_sections(struct kpatch_elf *kelf);
void kpatch_compare_correlated_rela_section(struct section *sec);

void kpatch_check_fentry_calls(struct kpatch_elf *kelf);

void kpatch_elf_teardown(struct kpatch_elf *kelf);
void kpatch_elf_free(struct kpatch_elf *kelf);
void kpatch_mark_ignored_sections(struct kpatch_elf *kelf);
void kpatch_mark_ignored_sections_same(struct kpatch_elf *kelf);
void kpatch_include_standard_elements(struct kpatch_elf *kelf);
void kpatch_include_debug_sections(struct kpatch_elf *kelf);
int kpatch_include_hook_elements(struct kpatch_elf *kelf);
void kpatch_include_force_elements(struct kpatch_elf *kelf);
int kpatch_include_new_globals(struct kpatch_elf *kelf);
void kpatch_print_changes(struct kpatch_elf *kelf);
void kpatch_dump_kelf(struct kpatch_elf *kelf);
void kpatch_process_special_sections(struct kpatch_elf *kelf);
void kpatch_verify_patchability(struct kpatch_elf *kelf);
void kpatch_migrate_included_elements(struct kpatch_elf *kelf, struct kpatch_elf **kelfout);
void kpatch_create_strings_elements(struct kpatch_elf *kelf);
void kpatch_create_patches_sections(struct kpatch_elf *kelf,
                                    struct lookup_table *table, char *hint,
                                    char *objname);
void kpatch_create_dynamic_rela_sections(struct kpatch_elf *kelf,
                                         struct lookup_table *table, char *hint,
                                         char *objname);
void kpatch_create_hooks_objname_rela(struct kpatch_elf *kelf, char *objname);
void kpatch_build_strings_section_data(struct kpatch_elf *kelf);
void kpatch_create_mcount_sections(struct kpatch_elf *kelf);
void kpatch_reorder_symbols(struct kpatch_elf *kelf);
void kpatch_strip_unneeded_syms(struct kpatch_elf *kelf,
                                struct lookup_table *table);
void kpatch_reindex_elements(struct kpatch_elf *kelf);
struct section *find_section_by_index(struct list_head *list, unsigned int index);
int is_rela_section(struct section *sec);
void kpatch_rebuild_rela_section_data(struct section *sec);
void kpatch_create_shstrtab(struct kpatch_elf *kelf);
void kpatch_create_strtab(struct kpatch_elf *kelf);
void kpatch_create_symtab(struct kpatch_elf *kelf);
void kpatch_write_output_elf(struct kpatch_elf *kelf, Elf *elf, char *outfile);
void kpatch_compare_correlated_elements(struct kpatch_elf *kelf);
void kpatch_mark_ignored_functions_same(struct kpatch_elf *kelf);
int kpatch_include_changed_functions(struct kpatch_elf *kelf);
struct section *find_section_by_name(struct list_head *list, const char *name);
struct section *create_section_pair(struct kpatch_elf *kelf, char *name,
                                    int entsize, int nr);
struct symbol *find_symbol_by_name(struct list_head *list, const char *name);
int offset_of_string(struct list_head *list, char *name);
