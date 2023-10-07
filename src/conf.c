/*
 * This file is part of the zlog Library.
 *
 * Copyright (C) 2011 by Hardy Simpson <HardySimpson1984@gmail.com>
 *
 * Licensed under the LGPL v2.1, see the file COPYING in base directory.
 */

#include "fmacros.h"
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

#include "conf.h"
#include "rule.h"
#include "format.h"
#include "level_list.h"
#include "rotater.h"
#include "zc_defs.h"
#include "zlog.h"

/*******************************************************************************/
// #define ZLOG_CONF_DEFAULT_FORMAT "default = \"%D %V [%p:%F:%L] %m%n\""
// #define ZLOG_CONF_DEFAULT_RULE "*.*        >stdout"
// #define ZLOG_CONF_DEFAULT_BUF_SIZE_MIN 1024
// #define ZLOG_CONF_DEFAULT_BUF_SIZE_MAX (2 * 1024 * 1024)
// #define ZLOG_CONF_DEFAULT_FILE_PERMS 0600
// #define ZLOG_CONF_DEFAULT_RELOAD_CONF_PERIOD 0
// #define ZLOG_CONF_DEFAULT_FSYNC_PERIOD 0
// #define ZLOG_CONF_BACKUP_ROTATE_LOCK_FILE "/tmp/zlog.lock"
/*******************************************************************************/

void zlog_conf_profile(zlog_conf_t * a_conf, int flag)
{
	int i;
	zlog_rule_t *a_rule;
	zlog_format_t *a_format;

	zc_assert(a_conf,);
	zc_profile(flag, "-conf[%p]-", a_conf);
	zc_profile(flag, "--global--");
	// zc_profile(flag, "---file[%s],mtime[%s]---", a_conf->file, a_conf->mtime);
	// zc_profile(flag, "---in-memory conf[%s]---", a_conf->cfg_ptr);
	// zc_profile(flag, "---strict init[%d]---", a_conf->strict_init);
	zc_profile(flag, "---buffer min[%ld]---", a_conf->buf_size_min);
	zc_profile(flag, "---buffer max[%ld]---", a_conf->buf_size_max);
	if (a_conf->default_format) {
		zc_profile(flag, "---default_format---");
		zlog_format_profile(a_conf->default_format, flag);
	}
	zc_profile(flag, "---file perms[0%o]---", a_conf->file_perms);
	zc_profile(flag, "---reload conf period[%ld]---", a_conf->reload_conf_period);
	zc_profile(flag, "---fsync period[%ld]---", a_conf->fsync_period);

	zc_profile(flag, "---rotate lock file[%s]---", a_conf->rotate_lock_file);
	if (a_conf->rotater) zlog_rotater_profile(a_conf->rotater, flag);

	if (a_conf->levels) zlog_level_list_profile(a_conf->levels, flag);

	if (a_conf->formats) {
		zc_profile(flag, "--format list[%p]--", a_conf->formats);
		zc_arraylist_foreach(a_conf->formats, i, a_format) {
			zlog_format_profile(a_format, flag);
		}
	}

	if (a_conf->rules) {
		zc_profile(flag, "--rule_list[%p]--", a_conf->rules);
		zc_arraylist_foreach(a_conf->rules, i, a_rule) {
			zlog_rule_profile(a_rule, flag);
		}
	}

	return;
}
/*******************************************************************************/
void zlog_conf_del(zlog_conf_t * a_conf)
{
	zc_assert(a_conf,);
	if (a_conf->rotater) zlog_rotater_del(a_conf->rotater);
	if (a_conf->levels) zlog_level_list_del(a_conf->levels);
	if (a_conf->default_format) zlog_format_del(a_conf->default_format);
	if (a_conf->formats) zc_arraylist_del(a_conf->formats);
	if (a_conf->rules) zc_arraylist_del(a_conf->rules);
	free(a_conf);
	zc_debug("zlog_conf_del[%p]");
	return;
}

static int zlog_conf_build(zlog_conf_t *a_conf, struct dds_logcfg *config);

zlog_conf_t *zlog_conf_new(struct dds_logcfg *config)
{
	zlog_conf_t *a_conf = NULL;

	a_conf = calloc(1, sizeof(zlog_conf_t));
	if (!a_conf) {
		zc_error("calloc fail, errno[%d]", errno);
		return NULL;
	}

	/* set default configuration start */
	a_conf->buf_size_min = config->bufferMin;
	a_conf->buf_size_max = config->bufferMax;
	
	strcpy(a_conf->rotate_lock_file, config->rotateLockFile);

	strcpy(a_conf->default_format_line, config->defaultFormat);

	a_conf->file_perms = config->filePerms;

	a_conf->fsync_period = config->fsyncPeriod;
	/* set default configuration end */

	a_conf->levels = zlog_level_list_new();
	if (!a_conf->levels) {
		zc_error("zlog_level_list_new fail");
		goto err;
	}

	a_conf->formats = zc_arraylist_new((zc_arraylist_del_fn) zlog_format_del);
	if (!a_conf->formats) {
		zc_error("zc_arraylist_new fail");
		goto err;
	}

	a_conf->rules = zc_arraylist_new((zc_arraylist_del_fn) zlog_rule_del);
	if (!a_conf->rules) {
		zc_error("init rule_list fail");
		goto err;
	}

	if (zlog_conf_build(a_conf, config)) {
		zc_error("zlog_conf_build fail");
		goto err;
	}

	zlog_conf_profile(a_conf, ZC_DEBUG);
	return a_conf;
err:
	zlog_conf_del(a_conf);
	return NULL;
}


static int zlog_conf_build(zlog_conf_t *a_conf, struct dds_logcfg *config)
{
	struct log_format_listelem *lf_elem = config->format_properties;
	struct log_rule_listelem *lr_elem = config->rule_properties;
	zlog_format_t *a_format = NULL;
	zlog_rule_t *a_rule = NULL;

	a_conf->rotater = zlog_rotater_new(a_conf->rotate_lock_file);
	if (!a_conf->rotater) {
		zc_error("zlog_rotater_new fail");
		return -1;
	}

	a_conf->default_format = zlog_format_new("default", a_conf->default_format_line, &(a_conf->time_cache_count));
	if (!a_conf->default_format) {
		zc_error("zlog_format_new fail");
		return -1;
	}

	while (lf_elem) {
		a_format = zlog_format_new (lf_elem->name, lf_elem->pattern, &(a_conf->time_cache_count));
		if (!a_format) {
			zc_error("zlog_format_new fail [%s]", lf_elem->name);
		}
		if (zc_arraylist_add(a_conf->formats, a_format)) {
			zlog_format_del(a_format);
			zc_error("zc_arraylist_add fail");
			return -1;
		}
		lf_elem = lf_elem->next;
	}

	while (lr_elem) {
		a_rule = zlog_rule_new(lr_elem, a_conf->levels, a_conf->default_format, a_conf->formats, a_conf->file_perms, a_conf->fsync_period, &(a_conf->time_cache_count));
		if (!a_rule) {
			zc_error("zlog_rule_new fail");
		}
		if (zc_arraylist_add(a_conf->rules, a_rule)) {
			zlog_rule_del(a_rule);
			zc_error("zc_arraylist_add fail");
			return -1;
		}
		lr_elem = lr_elem->next;
	}
	return 0;
}

