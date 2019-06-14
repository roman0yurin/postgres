#include <iostream>
#include <cstring>

extern "C" {
#include "postgres.h"

#include "fmgr.h"
#include "libpq/libpq.h"
#include "miscadmin.h"
#include "storage/fd.h"
#include "utils/builtins.h"
#include "postmaster/backend_parameters.h"
#include "postmaster/syslogger.h"
#include "postmaster/postmaster.h"
#include "storage/s_lock.h"
#include "storage/pmsignal.h"
#include "storage/lock.h"
#include "access/transam.h"
#include "storage/proc.h"
#include "storage/pg_shmem.h"
#include "utils/timestamp.h"
#include "storage/dsm.h"

extern pgsocket ListenSocket[MAXLISTEN];

#ifdef EXEC_BACKEND
void calculate_name_for_temp_file(char* tmpfilename, size_t max_size);

int write_backend_params_to_file(const char* tmpfilename, BackendParameters* param);

#ifndef WIN32
bool
save_backend_variables(BackendParameters *param, Port *port);
#else
bool save_backend_variables(BackendParameters *param, Port *port,
                            HANDLE childProcess, pid_t childPid);
#endif
#endif

Port* ConnCreate(int serverFd);
}

template <typename T>
void zeroMem(T* ptr) {
    std::memset(ptr, 0, sizeof(T));
}

/** Сохранение в файл параметров для запуска backend-процесса
 * (механизм, который используется в Postgres, когда задефайнен EXEC_BACKEND) */
PG_FUNCTION_INFO_V1(c60_save_backend_parameters);
Datum c60_save_backend_parameters([[maybe_unused]] PG_FUNCTION_ARGS) {
    const char* const fail_msg = "fail";

#ifdef EXEC_BACKEND
    char filename[MAXPGPATH];
    calculate_name_for_temp_file(filename, sizeof filename);

    BackendParameters params;
    zeroMem(&params);

    dsm_segment* seg = dsm_create(1024, 0);
    dsm_handle handle = dsm_segment_handle(seg); // при попытке подключиться по этому handler'у
                                                 // в своем процессе случается ошибка

    bool saved =
#ifndef WIN32
            save_backend_variables(&params, MyProcPort);
#else
    false;//TODO реализация под Windows
#endif

    if (!saved || write_backend_params_to_file(filename, &params) != 0) {
        PG_RETURN_TEXT_P(cstring_to_text(fail_msg));
    }

    text* result = cstring_to_text(filename);
    PG_RETURN_TEXT_P(result);
#else
    PG_RETURN_TEXT_P(cstring_to_text(fail_msg));
#endif


}
