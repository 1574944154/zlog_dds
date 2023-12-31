#ifndef __zlog_fmacro_h
#define __zlog_fmacro_h

// #define _DEFAULT_SOURCE

#if defined(__linux__) || defined(__OpenBSD__) || defined(_AIX)
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#ifndef _XOPEN_SOURCE_EXTENDED
#define _XOPEN_SOURCE_EXTENDED
#endif
#else
#define _XOPEN_SOURCE
#endif

#ifndef _LARGEFILE_SOURCE
#define _LARGEFILE_SOURCE
#endif
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif

#endif
