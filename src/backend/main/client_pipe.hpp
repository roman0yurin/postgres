#ifndef INVOKE_STRUCTS_HPP
#define INVOKE_STRUCTS_HPP

#include <vector>

class ClientWrapper
{
public:
    virtual ~ClientWrapper() {}
    static std::shared_ptr<ClientWrapper> connect(const char* server_lock_filename, key_t shm_key_id);
    virtual bool invoke(const void* request, size_t size, std::vector<char>& response) = 0;
};

namespace commands
{

struct Command
{
    Command() : command_id(-1) {}
    int command_id;
};

struct MetaByOid : public Command
{
    MetaByOid() { command_id = 0; }
    MetaByOid(int table_oid) : table_oid(table_oid) { command_id = 0; }
    int table_oid;
};

struct MetaByTableName : public Command
{
    MetaByTableName() { command_id = 1; }
    MetaByTableName(const char *table_name, const char *schema_name)
    {
        command_id = 1;
        setup(table_name, schema_name);
    }

    static constexpr size_t name_size = 64;

    void setup(const char *table_name, const char *schema_name)
    {
        copy_string(this->table_name, table_name);
        copy_string(this->schema_name, schema_name);
    }

    static inline void copy_string(char *dst, const char *src)
    {
        if(src && *src)
            strncpy(dst, src, name_size);
        else
            *dst = '\x00';
    }

    char table_name[name_size];
    char schema_name[name_size];
};

struct FetchByPK
{
    int id;
    bool use_binary_format;
};

struct FetchByPKOid : public MetaByOid, public FetchByPK
{
    FetchByPKOid() { command_id = 2; }
    FetchByPKOid(int table_oid, int id, bool use_binary_format)
    {
        command_id = 2;
        this->table_oid = table_oid;
        this->id = id;
        this->use_binary_format = use_binary_format;
    }
};

struct FetchByPKTableName : public MetaByTableName, public FetchByPK
{
    FetchByPKTableName() { command_id = 3; }
    FetchByPKTableName(const char *table_name, const char *schema_name, int id, bool use_binary_format)
    {
        command_id = 3;
        setup(table_name, schema_name);
        this->id = id;
        this->use_binary_format = use_binary_format;
    }
};

}

#endif