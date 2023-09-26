/*
 * This file is part of the zlog Library.
 *
 * Copyright (C) 2011 by Hardy Simpson <HardySimpson1984@gmail.com>
 *
 * Licensed under the LGPL v2.1, see the file COPYING in base directory.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#include "zc_defs.h"
#include "thread.h"
#include "spec.h"
#include "format.h"
#include "zlog.h"

void zlog_format_profile(zlog_format_t * a_format, int flag)
{

	zc_assert(a_format,);
	zc_profile(flag, "---format[%p][%s = %s(%p)]---",
		a_format,
		a_format->name,
		a_format->pattern,
		a_format->pattern_specs);

#if 0
	int i;
	zlog_spec_t *a_spec;
	zc_arraylist_foreach(a_format->pattern_specs, i, a_spec) {
		zlog_spec_profile(a_spec, flag);
	}
#endif

	return;
}

/*******************************************************************************/
void zlog_format_del(zlog_format_t * a_format)
{
	zc_assert(a_format,);
	if (a_format->pattern_specs) {
		zc_arraylist_del(a_format->pattern_specs);
	}
	zc_debug("zlog_format_del[%p]", a_format);
    free(a_format);
	return;
}

zlog_format_t *zlog_format_new(struct log_format_properties_listelem *elem, int *time_cache_count)
{
	int nscan = 0;
	zlog_format_t *a_format = NULL;
	int nread = 0;
	const char *p_start;
	const char *p_end;
	char *p;
	char *q;
	zlog_spec_t *a_spec;

	zc_assert(elem, NULL);

	a_format = calloc(1, sizeof(zlog_format_t));
	if (!a_format) {
		zc_error("calloc fail, errno[%d]", errno);
		return NULL;
	}

	/* line         default = "%d(%F %X.%l) %-6V (%c:%F:%L) - %m%n"
	 * name         default
	 * pattern      %d(%F %X.%l) %-6V (%c:%F:%L) - %m%n
	 */
	memset(a_format->name, 0x00, sizeof(a_format->name));
	strcpy(a_format->name, elem->name);

	for (p = a_format->name; *p != '\0'; p++) {
		if ((!isalnum(*p)) && (*p != '_')) {
			zc_error("a_format->name[%s] character is not in [a-Z][0-9][_]", a_format->name);
			goto err;
		}
	}

	memset(a_format->pattern, 0x00, sizeof(a_format->pattern));
	strcpy(a_format->pattern, elem->pattern);

	if (zc_str_replace_env(a_format->pattern, sizeof(a_format->pattern))) {
		zc_error("zc_str_replace_env fail");
		goto err;
	}

	a_format->pattern_specs =
	    zc_arraylist_new((zc_arraylist_del_fn) zlog_spec_del);
	if (!(a_format->pattern_specs)) {
		zc_error("zc_arraylist_new fail");
		goto err;
	}

	for (p = a_format->pattern; *p != '\0'; p = q) {
		a_spec = zlog_spec_new(p, &q, time_cache_count);
		if (!a_spec) {
			zc_error("zlog_spec_new fail");
			goto err;
		}

		if (zc_arraylist_add(a_format->pattern_specs, a_spec)) {
			zlog_spec_del(a_spec);
			zc_error("zc_arraylist_add fail");
			goto err;
		}
	}

	zlog_format_profile(a_format, ZC_DEBUG);
	return a_format;
err:
	zlog_format_del(a_format);
	return NULL;
}

/*******************************************************************************/
/* return 0	success, or buf is full
 * return -1	fail
 */
int zlog_format_gen_msg(zlog_format_t * a_format, zlog_thread_t * a_thread)
{
	int i;
	zlog_spec_t *a_spec;

	zlog_buf_restart(a_thread->msg_buf);

	zc_arraylist_foreach(a_format->pattern_specs, i, a_spec) {
		if (zlog_spec_gen_msg(a_spec, a_thread) == 0) {
			continue;
		} else {
			return -1;
		}
	}

	return 0;
}
