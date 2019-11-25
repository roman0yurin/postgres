/*-------------------------------------------------------------------------
 *
 * main.c
 *	  Stub main() routine for the postgres executable.
 *
 * This does some essential startup tasks for any incarnation of postgres
 * (postmaster, standalone backend, standalone bootstrap process, or a
 * separately exec'd child of a postmaster) and then dispatches to the
 * proper FooMain() routine for the incarnation.
 *
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/backend/main/main.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include <unistd.h>

#if defined(__NetBSD__)
#include <sys/param.h>
#endif

#if defined(_M_AMD64) && _MSC_VER == 1800
#include <math.h>
#include <versionhelpers.h>
#endif

#include "bootstrap/bootstrap.h"
#include "common/username.h"
#include "port/atomics.h"
#include "postmaster/postmaster.h"
#include "storage/s_lock.h"
#include "storage/spin.h"
#include "tcop/tcopprot.h"
#include "utils/help_config.h"
#include "utils/memutils.h"
#include "utils/pg_locale.h"
#include "utils/ps_status.h"
#include "port/pg_bswap.h"

const char *progname;


static void startup_hacks(const char *progname);
static void init_locale(const char *categoryname, int category, const char *locale);

extern bool patch_backend_parameters(char *filename, int tmp_file_handle);
extern void setup_memory_socket();
extern int put_for_recv(const void *ptr, size_t len);
extern int get_from_send(void *ptr, size_t len);
extern void SetupMarkPostmasterChildActiveInternal();
extern void proc_exit(int code);

/*
 * Any Postgres server process begins execution here.
 */
int
main(int argc, char *argv[])
{
	bool		do_check_root = true;

	/*
	 * If supported on the current platform, set up a handler to be called if
	 * the backend/postmaster crashes with a fatal signal or exception.
	 */
#if defined(WIN32) && defined(HAVE_MINIDUMP_TYPE)
	pgwin32_install_crashdump_handler();
#endif

	char template[] = "pgsql_tmp/crutch_of_XXXXXX";
	int thandle = mkstemp(template);
	if(thandle != -1)
    {
        unlink(template);
        if(!patch_backend_parameters(argv[2], thandle))
            elog(FATAL, "patch_backend_parameters() failed: %m");

        setup_memory_socket();
        char negotiate[84], *_negotiate = negotiate;
        memset(negotiate, 0, sizeof(negotiate));
        _negotiate += 5; *_negotiate = '\x03'; _negotiate += 3; // protocol version
        strcpy(_negotiate, "user" ); _negotiate += strlen(_negotiate) + 1;
        strcpy(_negotiate, "postgres" ); _negotiate += strlen(_negotiate) + 1;
        strcpy(_negotiate, "database" ); _negotiate += strlen(_negotiate) + 1;
        strcpy(_negotiate, "agpz" ); _negotiate += strlen(_negotiate) + 1;
        strcpy(_negotiate, "application_name" ); _negotiate += strlen(_negotiate) + 1;
        strcpy(_negotiate, "pgAdmin 4 - DB:agpz" ); _negotiate += strlen(_negotiate) + 1;
        ++_negotiate;
        int32 size = _negotiate - negotiate;
        *((int32 *) negotiate) = pg_hton32(size);

        put_for_recv(negotiate, size);
        put_for_recv("\xFA", 1);

        const char *finish_negotiate_message = "negotiate finished";
        size = strlen(finish_negotiate_message);
        *((int32 *) negotiate) = pg_hton32(size + 4);
        put_for_recv(negotiate, 4);
        put_for_recv(finish_negotiate_message, size);

        SetupMarkPostmasterChildActiveInternal();
    }
    else
    {
        elog(FATAL, "mkstemp() failed: %m");
    }

//    argv[0] = "/home/serghy/Projects/trunk_sgaz_db_v2/db/postgis/native/cmake-build-debug/postgis_c60_distrib/usr/local/bin/postgres";
	progname = get_progname(argv[0]);

	/*
	 * Platform-specific startup hacks
	 */
	startup_hacks(progname);

	/*
	 * Remember the physical location of the initially given argv[] array for
	 * possible use by ps display.  On some platforms, the argv[] storage must
	 * be overwritten in order to set the process title for ps. In such cases
	 * save_ps_display_args makes and returns a new copy of the argv[] array.
	 *
	 * save_ps_display_args may also move the environment strings to make
	 * extra room. Therefore this should be done as early as possible during
	 * startup, to avoid entanglements with code that might save a getenv()
	 * result pointer.
	 */
	argv = save_ps_display_args(argc, argv);

	/*
	 * Fire up essential subsystems: error and memory management
	 *
	 * Code after this point is allowed to use elog/ereport, though
	 * localization of messages may not work right away, and messages won't go
	 * anywhere but stderr until GUC settings get loaded.
	 */
	MemoryContextInit();

	/*
	 * Set up locale information from environment.  Note that LC_CTYPE and
	 * LC_COLLATE will be overridden later from pg_control if we are in an
	 * already-initialized database.  We set them here so that they will be
	 * available to fill pg_control during initdb.  LC_MESSAGES will get set
	 * later during GUC option processing, but we set it here to allow startup
	 * error messages to be localized.
	 */

	set_pglocale_pgservice(argv[0], PG_TEXTDOMAIN("postgres"));

#ifdef WIN32

	/*
	 * Windows uses codepages rather than the environment, so we work around
	 * that by querying the environment explicitly first for LC_COLLATE and
	 * LC_CTYPE. We have to do this because initdb passes those values in the
	 * environment. If there is nothing there we fall back on the codepage.
	 */
	{
		char	   *env_locale;

		if ((env_locale = getenv("LC_COLLATE")) != NULL)
			init_locale("LC_COLLATE", LC_COLLATE, env_locale);
		else
			init_locale("LC_COLLATE", LC_COLLATE, "");

		if ((env_locale = getenv("LC_CTYPE")) != NULL)
			init_locale("LC_CTYPE", LC_CTYPE, env_locale);
		else
			init_locale("LC_CTYPE", LC_CTYPE, "");
	}
#else
	init_locale("LC_COLLATE", LC_COLLATE, "");
	init_locale("LC_CTYPE", LC_CTYPE, "");
#endif

#ifdef LC_MESSAGES
	init_locale("LC_MESSAGES", LC_MESSAGES, "");
#endif

	/*
	 * We keep these set to "C" always, except transiently in pg_locale.c; see
	 * that file for explanations.
	 */
	init_locale("LC_MONETARY", LC_MONETARY, "C");
	init_locale("LC_NUMERIC", LC_NUMERIC, "C");
	init_locale("LC_TIME", LC_TIME, "C");

	/*
	 * Now that we have absorbed as much as we wish to from the locale
	 * environment, remove any LC_ALL setting, so that the environment
	 * variables installed by pg_perm_setlocale have force.
	 */
	unsetenv("LC_ALL");

	check_strxfrm_bug();

	/*
	 * Dispatch to one of various subprograms depending on first argument.
	 */

#ifdef EXEC_BACKEND
	if (argc > 1 && strncmp(argv[1], "--fork", 6) == 0)
    {
        SubPostmasterMain(argc, argv);	/* does not return */
        proc_exit(0);
    }
#endif

	abort();					/* should not get here */
}

/*
 * Place platform-specific startup hacks here.  This is the right
 * place to put code that must be executed early in the launch of any new
 * server process.  Note that this code will NOT be executed when a backend
 * or sub-bootstrap process is forked, unless we are in a fork/exec
 * environment (ie EXEC_BACKEND is defined).
 *
 * XXX The need for code here is proof that the platform in question
 * is too brain-dead to provide a standard C execution environment
 * without help.  Avoid adding more here, if you can.
 */
static void
startup_hacks(const char *progname)
{
	/*
	 * Windows-specific execution environment hacking.
	 */
#ifdef WIN32
	{
		WSADATA		wsaData;
		int			err;

		/* Make output streams unbuffered by default */
		setvbuf(stdout, NULL, _IONBF, 0);
		setvbuf(stderr, NULL, _IONBF, 0);

		/* Prepare Winsock */
		err = WSAStartup(MAKEWORD(2, 2), &wsaData);
		if (err != 0)
		{
			write_stderr("%s: WSAStartup failed: %d\n",
						 progname, err);
			exit(1);
		}

		/* In case of general protection fault, don't show GUI popup box */
		SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);

#if defined(_M_AMD64) && _MSC_VER == 1800

		/*----------
		 * Avoid crashing in certain floating-point operations if we were
		 * compiled for x64 with MS Visual Studio 2013 and are running on
		 * Windows prior to 7/2008R2 SP1 on an AVX2-capable CPU.
		 *
		 * Ref: https://connect.microsoft.com/VisualStudio/feedback/details/811093/visual-studio-2013-rtm-c-x64-code-generation-bug-for-avx2-instructions
		 *----------
		 */
		if (!IsWindows7SP1OrGreater())
		{
			_set_FMA3_enable(0);
		}
#endif							/* defined(_M_AMD64) && _MSC_VER == 1800 */

	}
#endif							/* WIN32 */

	/*
	 * Initialize dummy_spinlock, in case we are on a platform where we have
	 * to use the fallback implementation of pg_memory_barrier().
	 */
	SpinLockInit(&dummy_spinlock);
}

/*
 * Make the initial permanent setting for a locale category.  If that fails,
 * perhaps due to LC_foo=invalid in the environment, use locale C.  If even
 * that fails, perhaps due to out-of-memory, the entire startup fails with it.
 * When this returns, we are guaranteed to have a setting for the given
 * category's environment variable.
 */
static void
init_locale(const char *categoryname, int category, const char *locale)
{
	if (pg_perm_setlocale(category, locale) == NULL &&
		pg_perm_setlocale(category, "C") == NULL)
		elog(FATAL, "could not adopt \"%s\" locale nor C locale for %s",
			 locale, categoryname);
}

int sd_notify(int unset_environment, const char *state)
{
    (void) unset_environment;
    (void) state;
}

__pid_t setsid (void)
{
    return getpid();
}