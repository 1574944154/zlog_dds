/*
 * This file is part of the zlog Library.
 *
 * Copyright (C) 2011 by Hardy Simpson <HardySimpson1984@gmail.com>
 *
 * Licensed under the LGPL v2.1, see the file COPYING in base directory.
 */

#ifndef __zlog_h
#define __zlog_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h> /* for va_list */
#include <stdio.h> /* for size_t */
#include <stdint.h>

#include "category.h"

# if defined __GNUC__
#   define ZLOG_CHECK_PRINTF(m,n) __attribute__((format(printf,m,n)))
# else 
#   define ZLOG_CHECK_PRINTF(m,n)
# endif


struct log_format_properties_listelem {
  struct log_format_properties_listelem *next;
  char *name;
  char *pattern;
};

struct log_rule_properties_listelem {
  struct log_rule_properties_listelem *next;
  char *category;
  char *level;
  char *filePath;
  uint32_t archiveMaxSize;
  uint32_t archiveMaxCount;
  char *archivePattern;
  char *formatName;
};

struct ddsi_config_logcfg {
  uint32_t bufferMin;
  uint32_t bufferMax;
  char *rotateLockFile;
  char *defaultFormat;
  uint32_t filePerms;
  uint32_t fsyncPeriod;
  struct log_format_properties_listelem *format_properties;
  struct log_rule_properties_listelem *rule_properties;
};

int zlog_init(struct ddsi_config_logcfg *config);
void zlog_fini(void);

void zlog_profile(void);

zlog_category_t *zlog_get_category(const char *cname);
int zlog_level_enabled(zlog_category_t *category, const int level);

int zlog_level_switch(zlog_category_t * category, int level);
int zlog_level_enabled(zlog_category_t * category, int level);

void zlog(zlog_category_t * category,
	const char *file, size_t filelen,
	const char *func, size_t funclen,
	long line, int level,
	const char *format, ...) ZLOG_CHECK_PRINTF(8,9);
void vzlog(zlog_category_t * category,
	const char *file, size_t filelen,
	const char *func, size_t funclen,
	long line, int level,
	const char *format, va_list args);
void hzlog(zlog_category_t * category,
	const char *file, size_t filelen,
	const char *func, size_t funclen,
	long line, int level,
	const void *buf, size_t buflen);


typedef struct zlog_msg_s {
	char *buf;
	size_t len;
	char *path;
} zlog_msg_t;

typedef int (*zlog_record_fn)(zlog_msg_t *msg);
int zlog_set_record(const char *rname, zlog_record_fn record);

const char *zlog_version(void);

/******* useful macros, can be redefined at user's h file **********/

typedef enum {
	ZLOG_LEVEL_DEBUG = 20,
	ZLOG_LEVEL_INFO = 40,
	ZLOG_LEVEL_NOTICE = 60,
	ZLOG_LEVEL_WARN = 80,
	ZLOG_LEVEL_ERROR = 100,
	ZLOG_LEVEL_FATAL = 120
} zlog_level; 

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L
# if defined __GNUC__ && __GNUC__ >= 2
#  define __func__ __FUNCTION__
# else
#  define __func__ "<unknown>"
# endif
#endif

#if defined __STDC_VERSION__ && __STDC_VERSION__ >= 199901L
/* zlog macros */
#define zlog_fatal(cat, ...) \
	zlog(cat, __FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
	ZLOG_LEVEL_FATAL, __VA_ARGS__)
#define zlog_error(cat, ...) \
	zlog(cat, __FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
	ZLOG_LEVEL_ERROR, __VA_ARGS__)
#define zlog_warn(cat, ...) \
	zlog(cat, __FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
	ZLOG_LEVEL_WARN, __VA_ARGS__)
#define zlog_notice(cat, ...) \
	zlog(cat, __FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
	ZLOG_LEVEL_NOTICE, __VA_ARGS__)
#define zlog_info(cat, ...) \
	zlog(cat, __FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
	ZLOG_LEVEL_INFO, __VA_ARGS__)
#define zlog_debug(cat, ...) \
	zlog(cat, __FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
	ZLOG_LEVEL_DEBUG, __VA_ARGS__)

#elif defined __GNUC__
/* zlog macros */
#define zlog_fatal(cat, format, args...) \
	zlog(cat, __FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
	ZLOG_LEVEL_FATAL, format, ##args)
#define zlog_error(cat, format, args...) \
	zlog(cat, __FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
	ZLOG_LEVEL_ERROR, format, ##args)
#define zlog_warn(cat, format, args...) \
	zlog(cat, __FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
	ZLOG_LEVEL_WARN, format, ##args)
#define zlog_notice(cat, format, args...) \
	zlog(cat, __FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
	ZLOG_LEVEL_NOTICE, format, ##args)
#define zlog_info(cat, format, args...) \
	zlog(cat, __FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
	ZLOG_LEVEL_INFO, format, ##args)
#define zlog_debug(cat, format, args...) \
	zlog(cat, __FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
	ZLOG_LEVEL_DEBUG, format, ##args)

#endif

/* vzlog macros */
#define vzlog_fatal(cat, format, args) \
	vzlog(cat, __FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
	ZLOG_LEVEL_FATAL, format, args)
#define vzlog_error(cat, format, args) \
	vzlog(cat, __FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
	ZLOG_LEVEL_ERROR, format, args)
#define vzlog_warn(cat, format, args) \
	vzlog(cat, __FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
	ZLOG_LEVEL_WARN, format, args)
#define vzlog_notice(cat, format, args) \
	vzlog(cat, __FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
	ZLOG_LEVEL_NOTICE, format, args)
#define vzlog_info(cat, format, args) \
	vzlog(cat, __FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
	ZLOG_LEVEL_INFO, format, args)
#define vzlog_debug(cat, format, args) \
	vzlog(cat, __FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
	ZLOG_LEVEL_DEBUG, format, args)

/* hzlog macros */
#define hzlog_fatal(cat, buf, buf_len) \
	hzlog(cat, __FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
	ZLOG_LEVEL_FATAL, buf, buf_len)
#define hzlog_error(cat, buf, buf_len) \
	hzlog(cat, __FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
	ZLOG_LEVEL_ERROR, buf, buf_len)
#define hzlog_warn(cat, buf, buf_len) \
	hzlog(cat, __FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
	ZLOG_LEVEL_WARN, buf, buf_len)
#define hzlog_notice(cat, buf, buf_len) \
	hzlog(cat, __FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
	ZLOG_LEVEL_NOTICE, buf, buf_len)
#define hzlog_info(cat, buf, buf_len) \
	hzlog(cat, __FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
	ZLOG_LEVEL_INFO, buf, buf_len)
#define hzlog_debug(cat, buf, buf_len) \
	hzlog(cat, __FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
	ZLOG_LEVEL_DEBUG, buf, buf_len)



/* enabled macros */
#define zlog_fatal_enabled(zc) zlog_level_enabled(zc, ZLOG_LEVEL_FATAL)
#define zlog_error_enabled(zc) zlog_level_enabled(zc, ZLOG_LEVEL_ERROR)
#define zlog_warn_enabled(zc) zlog_level_enabled(zc, ZLOG_LEVEL_WARN)
#define zlog_notice_enabled(zc) zlog_level_enabled(zc, ZLOG_LEVEL_NOTICE)
#define zlog_info_enabled(zc) zlog_level_enabled(zc, ZLOG_LEVEL_INFO)
#define zlog_debug_enabled(zc) zlog_level_enabled(zc, ZLOG_LEVEL_DEBUG)

#ifdef __cplusplus
}
#endif

#endif
