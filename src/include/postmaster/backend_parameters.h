#pragma once

#include "postgres.h"
#include "access/transam.h"
#include "storage/s_lock.h"
#include "storage/lwlock.h"
#include "storage/pmsignal.h"
#include "storage/proc.h"

#include "lib/ilist.h"

/* The socket(s) we're listening to. */
#define MAXLISTEN	64

/* Type for a socket that can be inherited to a client process */
#ifdef WIN32
typedef struct
{
	SOCKET		origsocket;		/* Original socket value, or PGINVALID_SOCKET
								 * if not a socket */
	WSAPROTOCOL_INFO wsainfo;
} InheritableSocket;
#else
typedef int InheritableSocket;
#endif

typedef struct bkend
{
    pid_t		pid;			/* process id of backend */
    int32		cancel_key;		/* cancel key for cancels for this backend */
    int			child_slot;		/* PMChildSlot for this backend, if any */

    /*
     * Flavor of backend or auxiliary process.  Note that BACKEND_TYPE_WALSND
     * backends initially announce themselves as BACKEND_TYPE_NORMAL, so if
     * bkend_type is normal, you should check for a recent transition.
     */
    int			bkend_type;
    bool		dead_end;		/* is it going to send an error and quit? */
    bool		bgworker_notify;	/* gets bgworker start/stop notifications */
    dlist_node	elem;			/* list link in BackendList */
} Backend;

/*
 * Structure contains all variables passed to exec:ed backends
 */
typedef struct
{
    Port		port;
    InheritableSocket portsocket;
    char		DataDir[MAXPGPATH];
    pgsocket	ListenSocket[MAXLISTEN];
    int32		MyCancelKey;
    int			MyPMChildSlot;
#ifndef WIN32
    unsigned long UsedShmemSegID;
#else
    HANDLE		UsedShmemSegID;
#endif
    void	   *UsedShmemSegAddr;
    slock_t    *ShmemLock;
    VariableCache ShmemVariableCache;
    Backend    *ShmemBackendArray;
#ifndef HAVE_SPINLOCKS
    PGSemaphore *SpinlockSemaArray;
#endif
    int			NamedLWLockTrancheRequests;
    NamedLWLockTranche *NamedLWLockTrancheArray;
    LWLockPadded *MainLWLockArray;
    slock_t    *ProcStructLock;
    PROC_HDR   *ProcGlobal;
    PGPROC	   *AuxiliaryProcs;
    PGPROC	   *PreparedXactProcs;
    PMSignalData *PMSignalState;
    InheritableSocket pgStatSock;
    pid_t		PostmasterPid;
    TimestampTz PgStartTime;
    TimestampTz PgReloadTime;
    pg_time_t	first_syslogger_file_time;
    bool		redirection_done;
    bool		IsBinaryUpgrade;
    int			max_safe_fds;
    int			MaxBackends;
#ifdef WIN32
    HANDLE		PostmasterHandle;
	HANDLE		initial_signal_pipe;
	HANDLE		syslogPipe[2];
#else
    int			postmaster_alive_fds[2];
    int			syslogPipe[2];
#endif
    char		my_exec_path[MAXPGPATH];
    char		pkglib_path[MAXPGPATH];
    char		ExtraOptions[MAXPGPATH];
} BackendParameters;
