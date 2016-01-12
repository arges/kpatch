__livepatch_objects = ADDR(.livepatch.objects);
__livepatch_objects_end = ADDR(.livepatch.objects) + SIZEOF(.livepatch.objects);
__livepatch_funcs = ADDR(.livepatch.funcs);
__livepatch_funcs_end = ADDR(.livepatch.funcs) + SIZEOF(.livepatch.funcs);
__livepatch_relocs = ADDR(.livepatch.relocs);
__livepatch_relocs_end = ADDR(.livepatch.relocs) + SIZEOF(.livepatch.relocs);
