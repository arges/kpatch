/*
 * Copyright (C) 2013-2014 Josh Poimboeuf <jpoimboe@redhat.com>
 * Copyright (C) 2014 Seth Jennings <sjenning@redhat.com>
 * Copyright (C) 2016 Chris J Arges <chris.j.arges@canonical.com>
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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/kallsyms.h>
#include <linux/version.h>

#include <linux/livepatch.h>

struct klp_patch *lpatch;
extern struct klp_object __livepatch_objects[], __livepatch_objects_end[];

static int __init patch_init(void)
{
	int ret = 0;

	/* allocate patch structure */
	lpatch = kzalloc(sizeof(*lpatch), GFP_KERNEL);
	if (!lpatch)
		goto out;

	/* setup objects */
	lpatch->objs = __livepatch_objects;

	/* register patch */
	ret = klp_register_patch(lpatch);
	if (ret) {
		kfree(lpatch);
		return ret;
	}

	/* enable patch */
	ret = klp_enable_patch(lpatch);
	if (ret) {
		WARN_ON(klp_unregister_patch(lpatch));
		kfree(lpatch);
		return ret;
	}

	return 0;
out:
	kfree(lpatch);
	return ret;
}

static void __exit patch_exit(void)
{
	WARN_ON(klp_unregister_patch(lpatch));
}

module_init(patch_init);
module_exit(patch_exit);
MODULE_LICENSE("GPL");
