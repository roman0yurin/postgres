/*-------------------------------------------------------------------------
 *
 * port.h
 *	  Header for /port compatibility functions.
 *
 * Portions Copyright (c) 1996-2003, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * $PostgreSQL: pgsql/src/include/port.h,v 1.16 2004/02/02 00:11:31 momjian Exp $
 *
 *-------------------------------------------------------------------------
 */

#if !defined(_MSC_VER) && !defined(__BORLANDC__)
/* for thread.c */
#include <pwd.h>
#include <netdb.h>
#endif

/* Portable path handling for Unix/Win32 */
extern bool is_absolute_path(const char *filename);
extern char *first_path_separator(const char *filename);
extern char *last_path_separator(const char *filename);
extern char *get_progname(char *argv0);

extern char *simple_prompt(const char *prompt, int maxlen, bool echo);

#if defined(bsdi) || defined(netbsd)
extern int	fseeko(FILE *stream, off_t offset, int whence);
extern off_t ftello(FILE *stream);
#endif

#ifdef WIN32
/*
 * Win32 doesn't have reliable rename/unlink during concurrent access
 */
#ifndef FRONTEND
extern int	pgrename(const char *from, const char *to);
extern int	pgunlink(const char *path);

#define rename(from, to)	pgrename(from, to)
#define unlink(path)		pgunlink(path)
#endif

extern int	copydir(char *fromdir, char *todir);

/* Missing rand functions */
extern long	lrand48(void);
extern void	srand48(long seed);

/* Last parameter not used */
extern int	gettimeofday(struct timeval * tp, struct timezone * tzp);

#else

/*
 *	Win32 requires a special close for sockets and pipes, while on Unix
 *	close() does them all.
 */
#define closesocket close
#endif

/*
 * Default "extern" declarations or macro substitutes for library routines.
 * When necessary, these routines are provided by files in src/port/.
 */
#ifndef HAVE_CRYPT
extern char *crypt(const char *key, const char *setting);
#endif

#ifndef HAVE_FSEEKO
#define fseeko(a, b, c) fseek((a), (b), (c))
#define ftello(a) ftell((a))
#endif

#ifndef HAVE_GETOPT
extern int	getopt(int nargc, char *const * nargv, const char *ostr);
#endif

#ifndef HAVE_ISINF
extern int	isinf(double x);
#endif

#if !defined(HAVE_GETHOSTNAME) && defined(KRB4)
extern int	gethostname(char *name, int namelen);
#endif

#ifndef HAVE_RINT
extern double rint(double x);
#endif

#ifndef HAVE_INET_ATON
#if !defined(_MSC_VER) && !defined(__BORLANDC__)
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
extern int	inet_aton(const char *cp, struct in_addr * addr);
#endif

#ifndef HAVE_STRCASECMP
extern int	strcasecmp(char *s1, char *s2);
#endif

#ifndef HAVE_STRDUP
extern char *strdup(char const *);
#endif

#ifndef HAVE_RANDOM
extern long random(void);
#endif

#ifndef HAVE_SRANDOM
extern void srandom(unsigned int seed);
#endif

/* thread.h */
extern char *pqStrerror(int errnum, char *strerrbuf, size_t buflen);

#ifndef WIN32
extern int pqGetpwuid(uid_t uid, struct passwd * resultbuf, char *buffer,
		   size_t buflen, struct passwd **result);
#endif

extern int pqGethostbyname(const char *name,
				struct hostent *resultbuf,
				char *buffer, size_t buflen,
				struct hostent **result,
				int *herrno);

/* $PATH (or %PATH%) path separator */
#ifdef WIN32
#define PATHSEP ';'
#else
#define PATHSEP ':'
#endif

/* FIXME: [win32] Placeholder win32 replacements, to allow continued development */
#ifdef WIN32
#define fsync(a)	_commit(a)
#define sync()		_flushall()
#define WEXITSTATUS(w)  (((w) >> 8) & 0xff)
#define WIFEXITED(w)    (((w) & 0xff) == 0)
#define WIFSIGNALED(w)  (((w) & 0x7f) > 0 && (((w) & 0x7f) < 0x7f))
#define WTERMSIG(w)     ((w) & 0x7f)
#endif
