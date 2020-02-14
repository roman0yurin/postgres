extern "C" {

#include "postgres.h"
#include "fmgr.h"
#include "funcapi.h"
#include "miscadmin.h"

}

#include <string>

key_t server_pipe_init(const char* client_lock_path, std::string& live_lock_name, std::string& error);

extern "C" {

#ifdef PG_MODULE_MAGIC
PG_MODULE_MAGIC;
#endif

PG_FUNCTION_INFO_V1(c60_server_pipe_params);
Datum c60_server_pipe_params(PG_FUNCTION_ARGS)
{
    TupleDesc            tupdesc;
    if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
        ereport(ERROR,
                (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                    errmsg("function returning record called in context "
                           "that cannot accept type record")));

    if(fcinfo->nargs != 1 || !tupdesc || tupdesc->natts != 3 || tupdesc->attrs[0].atttypid != 23 ||
       tupdesc->attrs[1].atttypid != 1043 || tupdesc->attrs[2].atttypid != 1043)
        ereport(ERROR,(errmsg("Invalid function declaration")));

    AttInMetadata *attinmeta = TupleDescGetAttInMetadata(tupdesc);

    char *client_lock_path = PG_GETARG_CSTRING(0);
    std::string live_lock_name, error;
    key_t key = server_pipe_init(client_lock_path, live_lock_name, error);
    if(key == -1)
        ereport(ERROR,(errmsg("%s", error.c_str())));

    char **values = (char **) palloc(3 * sizeof(char *));
    char str_key[32], __pkglib_path[MAXPGPATH];
    sprintf(str_key, "%d", key);
    strlcpy(__pkglib_path, pkglib_path, MAXPGPATH);

    values[0] = str_key;
    values[1] = const_cast<char *>(live_lock_name.c_str());
    values[2] = __pkglib_path;

    /* build a tuple */
    HeapTuple tuple = BuildTupleFromCStrings(attinmeta, values);

    /* make the tuple into a datum */
    Datum result = HeapTupleGetDatum(tuple);

    /* clean up (this is not really necessary) */
    pfree(values);

    PG_RETURN_DATUM(result);
}

}