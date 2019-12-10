#include "postgres.h"

extern void proc_exit(int code);
extern void scan_table(Oid table_oid, Oid index_oid);

extern int pg_init(const char *program_file_path, const char *parameters_file_name, int params_count, char *paramsv[]);

int
main(int argc, char *argv[])
{
    char *paramsv[] = {
        "user", "postgres",
        "database", "sgaz",
        "application_name", "pgAdmin 4 - DB:agpz"
    };

    int params_count = sizeof(paramsv) / sizeof(char *);

    if(pg_init(argv[0], argv[2], params_count, paramsv) == 0)
        scan_table(3177838, 3196735);

    proc_exit(0);
}
