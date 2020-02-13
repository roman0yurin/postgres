extern "C" {

extern int pg_init(const char *program_file_path, const char *database_path, const char *parameters_file_name, int params_count, const char *paramsv[]);

}

#include <iostream>
#include <string>
#include <vector>

void connect(const std::string& program_file_path, const std::string& database_path, const std::string& parameters_file_name, const std::vector<std::string>& params)
{
    std::vector<const char *> paramsv(params.size());
    for(size_t i = 0 ; i < params.size() ; i++)
        paramsv[i] = params[i].c_str();

    ::pg_init(program_file_path.c_str(), database_path.c_str(), parameters_file_name.c_str(), params.size(), paramsv.data());
}
