extern void proc_exit(int code);
extern void scan_table();

extern int pg_init(const char *program_file_path, const char *database_path, const char *parameters_file_name, int params_count, const char *paramsv[]);

int
main(int argc, char *argv[])
{
    const char *paramsv[] = {
        "user", "postgres",
        "database", "sgaz",
        "application_name", "pgAdmin 4 - DB:agpz"
    };

    int params_count = sizeof(paramsv) / sizeof(char *);

    if(pg_init(argv[0], "/opt/pg/temp_data", argv[2], params_count, paramsv) == 0)
        scan_table();

    proc_exit(0);
}
