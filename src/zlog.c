/*
 * This file is part of the zlog Library.
 *
 * Copyright (C) 2011 by Hardy Simpson <HardySimpson1984@gmail.com>
 *
 * Licensed under the LGPL v2.1, see the file COPYING in base directory.
 */

#include "fmacros.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <pthread.h>

#include "conf.h"
#include "category_table.h"
#include "record_table.h"
#include "mdc.h"
#include "zc_defs.h"
#include "rule.h"
#include "version.h"

#define CATEGORY_CNT 15

/*******************************************************************************/
static pthread_rwlock_t zlog_env_lock = PTHREAD_RWLOCK_INITIALIZER;
zlog_conf_t *zlog_env_conf;
static pthread_key_t zlog_thread_key;
static zc_hashtable_t *zlog_env_categories;
static zc_hashtable_t *zlog_env_records;
static zlog_category_t *zlog_default_category;
static int zlog_env_is_init = 0;
static int zlog_env_init_version = 0;
static struct dds_logcfg logcfg;

static zlog_category_t *categories[CATEGORY_CNT];
static const char *category_names[] = {"discovery", "data", "radmin", "timing", "traffic", "topic", "tcp", "plist", "whc", "throttle", "rhc", "content", "shm", NULL};
/*******************************************************************************/
void add_format_property(char *name, char *pattern)
{
    struct log_format_listelem *node = malloc(sizeof(struct log_format_listelem));
    node->name = name;
    node->pattern = pattern;
    node->next = logcfg.format_properties;
    logcfg.format_properties = node;
}

void add_rule_property(char *category, char *level, char *filePath, uint32_t archiveMaxSize, uint32_t archiveMaxCount, char *archivePattern, char *formatName)
{
    struct log_rule_listelem *node = malloc(sizeof(struct log_rule_listelem));
    node->category = category;
    node->level = level;
    node->filePath = filePath;
    node->archiveMaxSize = archiveMaxSize;
    node->archiveMaxCount = archiveMaxCount;
    node->archivePattern = archivePattern;
    node->formatName = formatName;
    node->next = logcfg.rule_properties;
    logcfg.rule_properties = node;
}

void zlog_config_init(uint32_t bufferMin, uint32_t bufferMax, char *rotateLockFile, char *defaultFormat, uint32_t filePerms, uint32_t fsyncPeriod)
{
	logcfg.bufferMin = bufferMin;
	logcfg.bufferMax = bufferMax;
	logcfg.rotateLockFile = rotateLockFile;
	logcfg.defaultFormat = defaultFormat;
	logcfg.filePerms = filePerms;
	logcfg.fsyncPeriod = fsyncPeriod;
}

/* inner no need thread-safe */
static void zlog_fini_inner(void)
{
	/* pthread_key_delete(zlog_thread_key); */
	/* never use pthread_key_delete,
	 * it will cause other thread can't release zlog_thread_t 
	 * after one thread call pthread_key_delete
	 * also key not init will cause a core dump
	 */
	if (zlog_env_categories) zlog_category_table_del(zlog_env_categories);
	zlog_env_categories = NULL;
	zlog_default_category = NULL;
	if (zlog_env_records) zlog_record_table_del(zlog_env_records);
	zlog_env_records = NULL;
	if (zlog_env_conf) zlog_conf_del(zlog_env_conf);
	zlog_env_conf = NULL;
	return;
}

static void zlog_clean_rest_thread(void)
{
	zlog_thread_t *a_thread;
	a_thread = pthread_getspecific(zlog_thread_key);
	if (!a_thread) return;
	zlog_thread_del(a_thread);
	return;
}

static int zlog_init_inner(struct dds_logcfg *config)
{
	int rc = 0;

	/* the 1st time in the whole process do init */
	if (zlog_env_init_version == 0) {
		/* clean up is done by OS when a thread call pthread_exit */
		rc = pthread_key_create(&zlog_thread_key, (void (*) (void *)) zlog_thread_del);
		if (rc) {
			zc_error("pthread_key_create fail, rc[%d]", rc);
			goto err;
		}

		/* if some thread do not call pthread_exit, like main thread
		 * atexit will clean it 
		 */
		rc = atexit(zlog_clean_rest_thread);
		if (rc) {
			zc_error("atexit fail, rc[%d]", rc);
			goto err;
		}
		zlog_env_init_version++;
	} /* else maybe after zlog_fini() and need not create pthread_key */

	zlog_env_conf = zlog_conf_new(config);
	if (!zlog_env_conf) {
		zc_error("zlog_conf_new fail");
		goto err;
	}

	zlog_env_categories = zlog_category_table_new();
	if (!zlog_env_categories) {
		zc_error("zlog_category_table_new fail");
		goto err;
	}

	zlog_env_records = zlog_record_table_new();
	if (!zlog_env_records) {
		zc_error("zlog_record_table_new fail");
		goto err;
	}

	return 0;
err:
	zlog_fini_inner();
	return -1;
}

/*******************************************************************************/
int zlog_init()
{
	int rc;
	zc_debug("------zlog_init start------");
	zc_debug("------compile time[%s %s], version[%s]------", __DATE__, __TIME__, ZLOG_VERSION);

	rc = pthread_rwlock_wrlock(&zlog_env_lock);
	if (rc) {
		zc_error("pthread_rwlock_wrlock fail, rc[%d]", rc);
		return -1;
	}

	if (zlog_env_is_init) {
		zc_error("already init, use zlog_reload pls");
		goto err;
	}

	if (zlog_init_inner(&logcfg)) {
		zc_error("zlog_init_inner fail");
		goto err;
	}

	zlog_env_is_init = 1;
	zlog_env_init_version++;

	zc_debug("------zlog_init success end------");
	rc = pthread_rwlock_unlock(&zlog_env_lock);
	if (rc) {
		zc_error("pthread_rwlock_unlock fail, rc=[%d]", rc);
		return -1;
	}

	if (zlog_set_default_categories()) {
		zc_error("zlog_set_default_categories fail");
		return -1;
	}

	return 0;
err:
	zc_error("------zlog_init fail end------");
	rc = pthread_rwlock_unlock(&zlog_env_lock);
	if (rc) {
		zc_error("pthread_rwlock_unlock fail, rc=[%d]", rc);
		return -1;
	}
	return -1;
}

int zlog_set_default_categories()
{
	zlog_category_t *category = NULL;
	for(int i=0;category_names[i]!=NULL;i++) {
		category = zlog_get_category(category_names[i]);
		if (category==NULL) return -1;
		categories[i] = category;
	}
	return 0;
}

/*******************************************************************************/
void zlog_fini(void)
{
	int rc = 0;

	zc_debug("------zlog_fini start------");
	rc = pthread_rwlock_wrlock(&zlog_env_lock);
	if (rc) {
		zc_error("pthread_rwlock_wrlock fail, rc[%d]", rc);
		return;
	}

	if (!zlog_env_is_init) {
		zc_error("before finish, must zlog_init() or dzlog_init() first");
		goto exit;
	}

	zlog_fini_inner();
	zlog_env_is_init = 0;

exit:
	zc_debug("------zlog_fini end------");
	rc = pthread_rwlock_unlock(&zlog_env_lock);
	if (rc) {
		zc_error("pthread_rwlock_unlock fail, rc=[%d]", rc);
		return;
	}
	return;
}
/*******************************************************************************/
zlog_category_t *zlog_get_category(const char *cname)
{
	int rc = 0;
	zlog_category_t *a_category = NULL;

	zc_assert(cname, NULL);
	zc_debug("------zlog_get_category[%s] start------", cname);
	rc = pthread_rwlock_wrlock(&zlog_env_lock);
	if (rc) {
		zc_error("pthread_rwlock_wrlock fail, rc[%d]", rc);
		return NULL;
	}

	if (!zlog_env_is_init) {
		zc_error("never call zlog_init() or dzlog_init() before");
		a_category = NULL;
		goto err;
	}

	a_category = zlog_category_table_fetch_category(
				zlog_env_categories,
				cname,
				zlog_env_conf->rules);
	if (!a_category) {
		zc_error("zlog_category_table_fetch_category[%s] fail", cname);
		goto err;
	}

	zc_debug("------zlog_get_category[%s] success, end------ ", cname);
	rc = pthread_rwlock_unlock(&zlog_env_lock);
	if (rc) {
		zc_error("pthread_rwlock_unlock fail, rc=[%d]", rc);
		return NULL;
	}
	return a_category;
err:
	zc_error("------zlog_get_category[%s] fail, end------ ", cname);
	rc = pthread_rwlock_unlock(&zlog_env_lock);
	if (rc) {
		zc_error("pthread_rwlock_unlock fail, rc=[%d]", rc);
		return NULL;
	}
	return NULL;
}

/*******************************************************************************/
#define zlog_fetch_thread(a_thread, fail_goto) do {  \
	int rd = 0;  \
	a_thread = pthread_getspecific(zlog_thread_key);  \
	if (!a_thread) {  \
		a_thread = zlog_thread_new(zlog_env_init_version,  \
				zlog_env_conf->buf_size_min, zlog_env_conf->buf_size_max, \
				zlog_env_conf->time_cache_count); \
		if (!a_thread) {  \
			zc_error("zlog_thread_new fail");  \
			goto fail_goto;  \
		}  \
  \
		rd = pthread_setspecific(zlog_thread_key, a_thread);  \
		if (rd) {  \
			zlog_thread_del(a_thread);  \
			zc_error("pthread_setspecific fail, rd[%d]", rd);  \
			goto fail_goto;  \
		}  \
	}  \
  \
	if (a_thread->init_version != zlog_env_init_version) {  \
		/* as mdc is still here, so can not easily del and new */ \
		rd = zlog_thread_rebuild_msg_buf(a_thread, \
				zlog_env_conf->buf_size_min, \
				zlog_env_conf->buf_size_max);  \
		if (rd) {  \
			zc_error("zlog_thread_resize_msg_buf fail, rd[%d]", rd);  \
			goto fail_goto;  \
		}  \
  \
		rd = zlog_thread_rebuild_event(a_thread, zlog_env_conf->time_cache_count);  \
		if (rd) {  \
			zc_error("zlog_thread_resize_msg_buf fail, rd[%d]", rd);  \
			goto fail_goto;  \
		}  \
		a_thread->init_version = zlog_env_init_version;  \
	}  \
} while (0)

int zlog_level_switch(zlog_category_t * category, int level)
{
    // This is NOT thread safe.
    memset(category->level_bitmap, 0x00, sizeof(category->level_bitmap));
    category->level_bitmap[level / 8] |= ~(0xFF << (8 - level % 8));
    memset(category->level_bitmap + level / 8 + 1, 0xFF,
	    sizeof(category->level_bitmap) -  level / 8 - 1);

    return 0;
}

/*******************************************************************************/
void vzlog(enum dds_log_category lc,
	const char *file, size_t filelen,
	const char *func, size_t funclen,
	long line, int level,
	const char *format, va_list args)
{
	zlog_thread_t *a_thread;

	zlog_category_t *category = categories[lc];

	/* The bitmap determination here is not under the protection of rdlock.
	 * It may be changed by other CPU by zlog_reload() halfway.
	 *
	 * Old or strange value may be read here,
	 * but it is safe, the bitmap is valid as long as category exist,
	 * And will be the right value after zlog_reload()
	 *
	 * For speed up, if one log will not be output,
	 * There is no need to aquire rdlock.
	 */
	if (zlog_category_needless_level(category, level)) return;

	pthread_rwlock_rdlock(&zlog_env_lock);

	if (!zlog_env_is_init) {
		zc_error("never call zlog_init() or dzlog_init() before");
		goto exit;
	}

	zlog_fetch_thread(a_thread, exit);

	zlog_event_set_fmt(a_thread->event,
		category->name, category->name_len,
		file, filelen, func, funclen, line, level,
		format, args);

	if (zlog_category_output(category, a_thread)) {
		zc_error("zlog_output fail, srcfile[%s], srcline[%ld]", file, line);
		goto exit;
	}

	// if (zlog_env_conf->reload_conf_period &&
	// 	++zlog_env_reload_conf_count > zlog_env_conf->reload_conf_period ) {
	// 	/* under the protection of lock read env conf */
	// 	goto reload;
	// }

exit:
	pthread_rwlock_unlock(&zlog_env_lock);
	return;
// reload:
// 	pthread_rwlock_unlock(&zlog_env_lock);
// 	/* will be wrlock, so after unlock */
// 	if (zlog_reload((char *)-1)) {
// 		zc_error("reach reload-conf-period but zlog_reload fail, zlog-chk-conf [file] see detail");
// 	}
	// return;
}

void hzlog(enum dds_log_category lc,
	const char *file, size_t filelen,
	const char *func, size_t funclen,
	long line, int level,
	const void *buf, size_t buflen)
{
	zlog_thread_t *a_thread;

	zlog_category_t *category = categories[lc];

	if (zlog_category_needless_level(category, level)) return;

	pthread_rwlock_rdlock(&zlog_env_lock);

	if (!zlog_env_is_init) {
		zc_error("never call zlog_init() or dzlog_init() before");
		goto exit;
	}

	zlog_fetch_thread(a_thread, exit);

	zlog_event_set_hex(a_thread->event,
		category->name, category->name_len,
		file, filelen, func, funclen, line, level,
		buf, buflen);

	if (zlog_category_output(category, a_thread)) {
		zc_error("zlog_output fail, srcfile[%s], srcline[%ld]", file, line);
		goto exit;
	}

	// if (zlog_env_conf->reload_conf_period &&
	// 	++zlog_env_reload_conf_count > zlog_env_conf->reload_conf_period ) {
	// 	/* under the protection of lock read env conf */
	// 	goto reload;
	// }

exit:
	pthread_rwlock_unlock(&zlog_env_lock);
	return;
}

/*******************************************************************************/
// void zlog(enum dds_log_category lc,
// 	const char *file, size_t filelen, const char *func, size_t funclen,
// 	long line, const int level,
// 	const char *format, ...)
void zlog(enum dds_log_category lc,
	const char *file, size_t filelen, const char *func, size_t funclen,
	long line, const int level,
	const char *format, ...)
{
	zlog_thread_t *a_thread;
	va_list args;

	zlog_category_t *category = categories[lc];

	if (zlog_category_needless_level(category, level)) return;

	pthread_rwlock_rdlock(&zlog_env_lock);

	if (!zlog_env_is_init) {
		zc_error("never call zlog_init() or dzlog_init() before");
		goto exit;
	}

	zlog_fetch_thread(a_thread, exit);

	va_start(args, format);
	zlog_event_set_fmt(a_thread->event, category->name, category->name_len,
		file, filelen, func, funclen, line, level,
		format, args);
	if (zlog_category_output(category, a_thread)) {
		zc_error("zlog_output fail, srcfile[%s], srcline[%ld]", file, line);
		va_end(args);
		goto exit;
	}
	va_end(args);

exit:
	pthread_rwlock_unlock(&zlog_env_lock);
	return;
}


/*******************************************************************************/
void zlog_profile(void)
{
	int rc = 0;
	rc = pthread_rwlock_rdlock(&zlog_env_lock);
	if (rc) {
		zc_error("pthread_rwlock_wrlock fail, rc[%d]", rc);
		return;
	}
	zc_warn("------zlog_profile start------ ");
	zc_warn("is init:[%d]", zlog_env_is_init);
	zc_warn("init version:[%d]", zlog_env_init_version);
	zlog_conf_profile(zlog_env_conf, ZC_WARN);
	zlog_record_table_profile(zlog_env_records, ZC_WARN);
	zlog_category_table_profile(zlog_env_categories, ZC_WARN);
	if (zlog_default_category) {
		zc_warn("-default_category-");
		zlog_category_profile(zlog_default_category, ZC_WARN);
	}
	zc_warn("------zlog_profile end------ ");
	rc = pthread_rwlock_unlock(&zlog_env_lock);
	if (rc) {
		zc_error("pthread_rwlock_unlock fail, rc=[%d]", rc);
		return;
	}
	return;
}
/*******************************************************************************/
int zlog_set_record(const char *rname, zlog_record_fn record_output)
{
	int rc = 0;
	int rd = 0;
	zlog_rule_t *a_rule;
	zlog_record_t *a_record;
	int i = 0;

	zc_assert(rname, -1);
	zc_assert(record_output, -1);

	rd = pthread_rwlock_wrlock(&zlog_env_lock);
	if (rd) {
		zc_error("pthread_rwlock_rdlock fail, rd[%d]", rd);
		return -1;
	}

	if (!zlog_env_is_init) {
		zc_error("never call zlog_init() or dzlog_init() before");
		goto zlog_set_record_exit;
	}

	a_record = zlog_record_new(rname, record_output);
	if (!a_record) {
		rc = -1;
		zc_error("zlog_record_new fail");
		goto zlog_set_record_exit;
	}

	rc = zc_hashtable_put(zlog_env_records, a_record->name, a_record);
	if (rc) {
		zlog_record_del(a_record);
		zc_error("zc_hashtable_put fail");
		goto zlog_set_record_exit;
	}

	zc_arraylist_foreach(zlog_env_conf->rules, i, a_rule) {
		zlog_rule_set_record(a_rule, zlog_env_records);
	}

      zlog_set_record_exit:
	rd = pthread_rwlock_unlock(&zlog_env_lock);
	if (rd) {
		zc_error("pthread_rwlock_unlock fail, rd=[%d]", rd);
		return -1;
	}
	return rc;
}
/*******************************************************************************/
int zlog_level_enabled(zlog_category_t *category, const int level)
{
	return category && ((zlog_category_needless_level(category, level) == 0));
}

const char *zlog_version(void) { return ZLOG_VERSION; }
