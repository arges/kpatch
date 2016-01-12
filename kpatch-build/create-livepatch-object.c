/*
 * create-livepatch-object.c
 *
 * Copyright (C) 2013-2014 Josh Poimboeuf <jpoimboe@redhat.com>
 * Copyright (C) 2014 Seth Jennings <sjenning@redhat.com>
 * Copyright (C) 2015-2016 Chris J Arges <chris.j.arges@canonical.com>
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
#include "livepatch.h"

char *childobj;
enum loglevel loglevel;

struct arguments {
	char *args[2];
	int debug;
};

/*
 * There are quite a few similar structures at play in this file:
 * - livepatch.h structs prefixed with klp_*
 * - kpatch-patch.h structs prefixed with kpatch_patch_*
 * - local scaffolding structs prefixed with patch_*
 *
 * The naming of the struct variables follows this convention:
 * - livepatch struct being with "l" (e.g. lfunc)
 * - kpatch_patch structs being with "k" (e.g. kfunc)
 * - local scaffolding structs have no prefix (e.g. func)
 *
 *  The program reads in kpatch_patch structures, arranges them into the
 *  scaffold structures, then creates a livepatch structure suitable for
 *  registration with the livepatch kernel API.  The scaffold structs only
 *  exist to allow the construction of the klp_patch struct.  Once that is
 *  done, the scaffold structs are no longer needed.
 */

static LIST_HEAD(patch_objects);
static int patch_objects_nr;
struct patch_object {
	struct list_head list;
	struct list_head funcs;
	struct list_head relocs;
	const char *name;
	int funcs_nr, relocs_nr;
};

struct patch_func {
	struct list_head list;
	struct kpatch_patch_func *kfunc;
};

struct patch_reloc {
	struct list_head list;
	struct kpatch_patch_dynrela *kdynrela;
};

////////////////////////////////////////////////////////////////////////////////
// FIXME: Remove after debugging.

void print_kpatch_patch_func(struct kpatch_patch_func *func)
{
	printf("kpatch_patch_func %p = {\n", func);
	printf("\t.name     =\t0x%08lx\n", (long unsigned int)func->name);
	printf("\t.new_addr =\t0x%08lx\n", (long unsigned int)func->new_addr);
	printf("\t.old_addr =\t0x%08lx\n", func->old_addr);
	printf("};\n");
}

void print_klp_func(struct klp_func *func)
{
	printf("klp_func %p = {\n", func);
	printf("\t.old_name =\t0x%08lx\n", (long unsigned int)func->old_name);
	printf("\t.new_func =\t0x%08lx\n", (long unsigned int)func->new_func);
	printf("\t.old_addr =\t0x%08lx\n", func->old_addr);
	printf("};\n");
}

void print_kpatch_patch_dynrela(struct kpatch_patch_dynrela *dynrela)
{
	printf("kpatch_patch_dynrela %p = {\n", dynrela);
	printf("\t.name     =\t0x%08lx\n", (long unsigned int)dynrela->name);
	printf("\t.dest =\t0x%08lx\n", (long unsigned int)dynrela->dest);
	printf("\t.src =\t0x%08lx\n", (long unsigned int)dynrela->src);
	printf("};\n");
}

void print_klp_reloc(struct klp_reloc *reloc)
{
	printf("klp_reloc %p = {\n", reloc);
	printf("\t.name =\t0x%08lx\n", (long unsigned int)reloc->name);
	printf("\t.loc =\t0x%08lx\n", (long unsigned int)reloc->loc);
	printf("\t.val =\t0x%08lx\n", (long unsigned int)reloc->val);
	printf("};\n");
}

void xxd(void *mem, size_t len)
{
	size_t i;
	for(i = 0; i < len; i++) {
                if(i % 8 == 0)
			printf("%04lx: ", i);
		if(i < len) {
			printf("%02x", 0xff & ((char*)mem)[i]);
			if (((i+1) % 8) == 0)
				printf("\n");
                }
        }
}

////////////////////////////////////////////////////////////////////////////////

static struct patch_object *patch_alloc_new_object(const char *name)
{
	struct patch_object *object;

	object = calloc(1, sizeof(*object));
	if (!object)
		return NULL;
	INIT_LIST_HEAD(&object->funcs);
	INIT_LIST_HEAD(&object->relocs);

	if (strcmp(name, "vmlinux"))
		object->name = name;
	list_add(&object->list, &patch_objects);
	patch_objects_nr++;
	return object;
}

static struct patch_object *patch_find_object_by_name(const char *name)
{
	struct patch_object *object;

	list_for_each_entry(object, &patch_objects, list)
		if ((!strcmp(name, "vmlinux") && !object->name) ||
		    (object->name && !strcmp(object->name, name)))
			return object;
	return patch_alloc_new_object(name);
}

static int patch_add_func_to_object(struct kpatch_patch_func *kfunc, char *name, char *objname)
{
	struct patch_func *func;
	struct patch_object *object;

	func = calloc(1, sizeof(*func));
	if (!func)
		return -ENOMEM;
	INIT_LIST_HEAD(&func->list);
	func->kfunc = kfunc;

	object = patch_find_object_by_name(objname);
	if (!object) {
		free(func);
		return -ENOMEM;
	}
	list_add(&func->list, &object->funcs);
	object->funcs_nr++;
	return 0;
}

static int patch_add_reloc_to_object(struct kpatch_patch_dynrela *kdynrela, char *name, char *objname)
{
	struct patch_reloc *reloc;
	struct patch_object *object;

	reloc = calloc(1, sizeof(*reloc));
	if (!reloc)
		return -ENOMEM;
	INIT_LIST_HEAD(&reloc->list);
	reloc->kdynrela = kdynrela;

	object = patch_find_object_by_name(objname);
	if (!object) {
		free(reloc);
		return -ENOMEM;
	}
	list_add(&reloc->list, &object->relocs);
	object->relocs_nr++;
	return 0;
}

void kpatch_include_livepatch_elements(struct kpatch_elf *kelf)
{
	struct section *sec;
	struct symbol *sym;

	list_for_each_entry(sec, &kelf->sections, list) {
		if (strcmp(sec->name, ".kpatch.strings") &&
		    strcmp(sec->name, ".kpatch.funcs") &&
		    strcmp(sec->name, ".rela.kpatch.funcs") &&
		    strcmp(sec->name, ".kpatch.dynrelas") &&
		    strcmp(sec->name, ".rela.kpatch.dynrelas") &&
		    strcmp(sec->name, ".kpatch.checksum")
		   ) {
			sec->include = 1;
			if (sec->secsym) {
				sec->secsym->include = 1;
			}

			list_for_each_entry(sym, &kelf->symbols, list) {
				sym->include = 1;
			}
		}
	}

	/* include the NULL symbol */
	list_entry(kelf->symbols.next, struct symbol, list)->include = 1;
}

char *kpatch_get_func_string(struct kpatch_elf *kelf, int index, int offset)
{
	size_t struct_size = sizeof(struct kpatch_patch_func);
	struct section *sec;
	struct rela *rela;

	sec = find_section_by_name(&kelf->sections, ".rela.kpatch.funcs");
	list_for_each_entry(rela, &sec->relas, list) {
		if (rela->offset == ((index * struct_size) + offset))
			return (rela->sym->sec->data->d_buf + rela->addend);
	}
	return NULL;
}

char *kpatch_get_dynrela_string(struct kpatch_elf *kelf, int index, int offset)
{
	size_t struct_size = sizeof(struct kpatch_patch_dynrela);
	struct section *sec;
	struct rela *rela;

	sec = find_section_by_name(&kelf->sections, ".rela.kpatch.dynrelas");
	list_for_each_entry(rela, &sec->relas, list) {
		if (rela->offset == ((index * struct_size) + offset))
			return (rela->sym->sec->data->d_buf + rela->addend);
	}
	return NULL;
}

// FIXME: do we need all this data?
struct kpatch_klp {
	struct klp_object *objects;
	struct klp_func *funcs;
	struct klp_reloc *relocs;
	int nr_objects;
	int nr_funcs;
	int nr_relocs;
};

int kpatch_create_livepatch_structures(struct kpatch_elf *kelf, struct kpatch_klp *klp)
{
	struct section *sec;
	struct kpatch_patch_func *kfunc;
	struct kpatch_patch_func *__kpatch_funcs;
	//struct kpatch_patch_func *kpatch_funcs;
	size_t __kpatch_funcs_size, kpatch_funcs_total;

	struct kpatch_patch_dynrela *kdynrela;
	struct kpatch_patch_dynrela *__kpatch_dynrelas;
	//struct kpatch_patch_dynrela *kpatch_dynrelas;
	size_t __kpatch_dynrelas_size, kpatch_dynrelas_total;

	struct patch_object *object;
	struct patch_func *func;
	struct patch_reloc *reloc;
	struct klp_object *lobjects, *lobject;
	struct klp_func *lfuncs, *lfunc;
	struct klp_reloc *lrelocs, *lreloc;

	int i,j,k, ret = 0;

	/* process kpatch funcs make a copy so we can write into memory */
	log_debug("\n=== processing .kpatch.funcs ===\n");
	sec = find_section_by_name(&kelf->sections, ".kpatch.funcs");
	if (!sec)
		ERROR("couldn't find section: .kpatch.funcs");

	/* set pointers to kpatch_funcs data */
	__kpatch_funcs =  (struct kpatch_patch_func *)sec->data->d_buf;
	__kpatch_funcs_size = sec->data->d_size;
	kpatch_funcs_total = (__kpatch_funcs_size / sizeof(struct kpatch_patch_func));

	//cja
	log_debug("kpatch_funcs:\n");
	xxd(__kpatch_funcs, __kpatch_funcs_size);

	/* allocate and copy into new structure */
	//kpatch_funcs = (struct kpatch_patch_func *)malloc(__kpatch_funcs_size);
	//memcpy(kpatch_funcs, __kpatch_funcs, __kpatch_funcs_size);

	/* organize functions and relocs by object in scaffold */
	for (i = 0; i < kpatch_funcs_total; i++) {
		kfunc = &__kpatch_funcs[i];

		//cja
		print_kpatch_patch_func(kfunc);

		/* lookup relocated names */
		char *kfunc_name = kpatch_get_func_string(kelf, i,
			       offsetof(struct kpatch_patch_func, name));
		char *kfunc_objname = kpatch_get_func_string(kelf, i,
				  offsetof(struct kpatch_patch_func, objname));

		void * kfunc_old_addr = (void *)kpatch_get_func_string(kelf, i,
			offsetof(struct kpatch_patch_func, old_addr));

		/* add function to object list */
		ret = patch_add_func_to_object(kfunc, kfunc_name, kfunc_objname);
		if (ret)
			return 1;

		log_debug("added kpatch name %s objname %s old_addr %p\n", kfunc_name, kfunc_objname, kfunc_old_addr);
	}

	/* process kpatch dynrelas */
	log_debug("\n=== processing .kpatch.dynrelas ===\n");
	sec = find_section_by_name(&kelf->sections, ".kpatch.dynrelas");
	if (!sec)
		ERROR("couldn't find section: .kpatch.dynrelas");

	__kpatch_dynrelas =  (struct kpatch_patch_dynrela *)sec->data->d_buf;
	__kpatch_dynrelas_size = sec->data->d_size;
	kpatch_dynrelas_total = (__kpatch_dynrelas_size / sizeof(struct kpatch_patch_dynrela));

	//cja
	//log_debug("kpatch_dynrelas:\n");
	//xxd(__kpatch_dynrelas, __kpatch_dynrelas_size);

	/* allocate and copy into new structure */
	//kpatch_dynrelas = (struct kpatch_patch_dynrela *)malloc(__kpatch_dynrelas_size);
	//memcpy(kpatch_dynrelas, __kpatch_dynrelas, __kpatch_dynrelas_size);

	/* organize functions and relocs by object in scaffold */
	for (i = 0; i < kpatch_dynrelas_total; i++) {
		kdynrela = &__kpatch_dynrelas[i];
		//cja
		print_kpatch_patch_dynrela(kdynrela);

		/* lookup relocated names */
		char *kdynrela_name = kpatch_get_dynrela_string(kelf, i,
			       offsetof(struct kpatch_patch_dynrela, name));
		char *kdynrela_objname = kpatch_get_dynrela_string(kelf, i,
				  offsetof(struct kpatch_patch_dynrela, objname));

		/* add function to object list */
		ret = patch_add_reloc_to_object(kdynrela, kdynrela_name, kdynrela_objname);
		if (ret)
			return 1;

		/*log_debug("added reloc name %s objname %s src %lu\n",
			  kdynrela->name, kdynrela->objname, kdynrela->src);*/
	}


	/* Allocate and zero memory for linear livepatch structures.
	 * Always allocate one more structure to act as a terminator.
	 * The structure layout (relocs will be similar to funcs):
	 *

	+-----------------+
	|obj1 |obj2 |null |   objects
	++-----+----------+
	 |     |
	 |     +-----------+
	 |                 |
	+v-----------------v----------------+
	|func1|func2|null |func1|func2|null |   functions
	+-----------------------------------+

	 */

	lobjects = calloc(patch_objects_nr + 1, sizeof(struct klp_object));
	if (!lobjects)
		ERROR("Couldn't allocate memory for klp_objects");

	lfuncs = calloc(kpatch_funcs_total + patch_objects_nr, sizeof(struct klp_func));
	if (!lfuncs)
		ERROR("Couldn't allocate memory for klp_funcs");

	lrelocs = calloc(kpatch_dynrelas_total + patch_objects_nr, sizeof(struct klp_reloc));
	if (!lrelocs)
		ERROR("Couldn't allocate memory for klp_relocs");

	/* iterate and fill structures */
	i = 0; //objects
	j = 0; //funcs
	k = 0; //relocs
	list_for_each_entry(object, &patch_objects, list) {
		lobject = &lobjects[i];
		lobject->name = object->name;

		/* set funcs pointer to beginning of function pointers */
		lobject->funcs = &lfuncs[j];
		list_for_each_entry(func, &object->funcs, list) {
			lfunc = &lfuncs[j];
			lfunc->old_name = func->kfunc->name;
			lfunc->old_addr = func->kfunc->old_addr;
			lfunc->new_func = (void *)func->kfunc->new_addr;
			j++;
		}
		j++;	/* skip one structure for padding */

		/* add relocs */
		lobject->relocs = &lrelocs[k];
		list_for_each_entry(reloc, &object->relocs, list) {
			lreloc = &lrelocs[k];
			lreloc->loc = reloc->kdynrela->dest;
			lreloc->type = reloc->kdynrela->type;
			lreloc->name = reloc->kdynrela->name;
			lreloc->addend = reloc->kdynrela->addend;
			lreloc->external = reloc->kdynrela->external;
			k++;
		}
		k++;	/* skip one structure for padding */

		i++;
	}
	i++;	/* add object padding */

	/* sanity check here */
	log_debug("\n=== summary ===\n");
	log_debug("found: %d objects, %d funcs, %d relocs\n", i, j ,k);
	log_debug("expected %d objects %lu funcs %lu relocs\n",
		  patch_objects_nr + 1, kpatch_funcs_total + patch_objects_nr,
		  kpatch_dynrelas_total + patch_objects_nr);


	//cja
	log_debug("klp objects:\n");
	xxd(lobjects, sizeof(*lobjects) * i);
	log_debug("klp funcs:\n");
	xxd(lfuncs, sizeof(*lfuncs) * j);
	//log_debug("klp relocs:\n");
	//xxd(lrelocs, sizeof(*lrelocs) * k);

	// FIXME what is necessary?
	/* setup return structures */
	klp->objects = lobjects;
	klp->nr_objects = patch_objects_nr;
	klp->funcs = lfuncs;
	klp->nr_funcs = j;
	klp->relocs = lrelocs;
	klp->nr_relocs = k;

	return 0;
}

int kpatch_dump_livepatch_structures(struct kpatch_klp *klp)
{
	/*struct klp_object *lobject;
	struct klp_func *lfunc;
	struct klp_reloc *lreloc;*/
	int i,j,k;

	for (i = 0; i < klp->nr_objects; i++) {
		for (j = 0; j < klp->nr_funcs; j++) {
			print_klp_func(&klp->funcs[j]);
		}
		for (k = 0; k < klp->nr_relocs; k++) {
			print_klp_reloc(&klp->relocs[k]);
		}
	}
	#if 0
	/* dump it out! */
	for (lobject = klp->objects; lobject->funcs; lobject++) {
		for (lfunc = lobject->funcs; lfunc->old_name; lfunc++) {
			log_debug("klp func old_name %s object name %s\n",
				  lfunc->old_name, lobject->name);
			print_klp_func(lfunc);
		}
		for (lreloc = lobject->relocs; lreloc->name; lreloc++) {
			log_debug("klp reloc name %s object name %s\n",
				  lreloc->name, lobject->name);
		}
	}
	#endif

	return 0;
}

void kpatch_create_livepatch_sections(struct kpatch_elf *kelf, struct kpatch_klp *klp)
{
	struct section *sec;

	/* create text/rela section pair */
	sec = create_section_pair(kelf, ".livepatch.objects", sizeof(*klp->objects),
		klp->nr_objects+1);
	sec->data->d_buf = klp->objects;

	sec = create_section_pair(kelf, ".livepatch.funcs", sizeof(*klp->funcs),
		klp->nr_funcs+1);
	sec->data->d_buf = klp->funcs;

	sec = create_section_pair(kelf, ".livepatch.relocs", sizeof(*klp->relocs),
		klp->nr_relocs+1);
	sec->data->d_buf = klp->relocs;

}

static char args_doc[] = "input.o output.o";

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
			if (state->arg_num >= 2)
				/* Too many arguments. */
				argp_usage (state);
			arguments->args[state->arg_num] = arg;
			break;
		case ARGP_KEY_END:
			if (state->arg_num < 2)
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
	struct kpatch_elf *kelf_in, *kelf_out;
	struct section *sec, *symtab;
	struct kpatch_klp klp;
	struct arguments arguments;

	arguments.debug = 0;
	argp_parse (&argp, argc, argv, 0, 0, &arguments);
	if (arguments.debug)
		loglevel = DEBUG;

	loglevel = NORMAL;
	elf_version(EV_CURRENT);
	childobj = basename(arguments.args[0]);
	kelf_in = kpatch_elf_open(argv[1]);

	/* output elf */
	loglevel = DEBUG;
	kpatch_include_livepatch_elements(kelf_in);

	/* create livepatch structures */
	kpatch_create_livepatch_structures(kelf_in, &klp);
	kpatch_dump_livepatch_structures(&klp);
	loglevel = NORMAL;

	/* migrate sections to new elf */
	kpatch_migrate_included_elements(kelf_in, &kelf_out);
	kpatch_elf_teardown(kelf_in);

	/* insert new sections here */
	loglevel = DEBUG;
	kpatch_create_livepatch_sections(kelf_out, &klp);
	loglevel = NORMAL;

	kpatch_create_strings_elements(kelf_out);
	kpatch_build_strings_section_data(kelf_out);

	/* build strings and symbols */
	kpatch_reorder_symbols(kelf_out);
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

	/* create tables */
	kpatch_create_shstrtab(kelf_out);
	kpatch_create_strtab(kelf_out);
	kpatch_create_symtab(kelf_out);

	/* output object file */
	kpatch_dump_kelf(kelf_out);
	kpatch_write_output_elf(kelf_out, kelf_in->elf, argv[2]);

	return 0;
}
