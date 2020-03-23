extern "C" {

#include "postgres.h"
#include "miscadmin.h"
#include "fmgr.h"
#include "funcapi.h"
#include "access/xact.h"
#include "access/htup.h"
#include "storage/fd.h"

}

//#define DEBUG_SERVER

#include <string>
#include <thread>
#include <optional>
#include <future>
#include <chrono>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <boost/interprocess/sync/file_lock.hpp>
#include <boost/interprocess/sync/named_semaphore.hpp>
#include <boost/interprocess/mapped_region.hpp>
#include <boost/interprocess/sync/interprocess_semaphore.hpp>
#include <boost/interprocess/xsi_shared_memory.hpp>
#include "exchange_buffer.hpp"
#include "client_pipe.hpp"

extern bool metaByTableOid(int32_t table_oid, const std::function<void(const void*, size_t)>& func);
extern bool metaByTableName(const char* table_name, const char * schema_name, const std::function<void(const void*, size_t)>& func);
extern void fetchByKeyTableOid(int32_t table_oid, int32_t key_value, bool use_binary_format,
                               const std::function<void(const void*, size_t)>& func);
extern void fetchByKeyTableName(const char* table_name, const char* schema_name, int32_t key_value,
                                bool use_binary_format, const std::function<void(const void*, size_t)>& func);

namespace
{

#if !defined(DEBUG_SERVER)
const char* get_data_path()
{
#if defined(__linux) || defined(__linux__) || defined(linux)
    return "/tmp";
#else
    return DataDir;
#endif
}
#endif

boost::interprocess::file_lock get_locked_temp(std::string& live_lock_name)
{
#if defined(DEBUG_SERVER)
    live_lock_name = "/db/pg/temp_data/pgsql_tmp/live_lock_GomRxR";
    boost::interprocess::file_lock result(live_lock_name.c_str());
    if(result.try_lock())
        return result;
    else
        throw std::runtime_error(std::string("can't lock generated temp file: ") + live_lock_name);
#else
    static const char lock_suffix[] = ".live_lock_XXXXXX";
    char temp_path[MAXPGPATH];
    size_t len = strnlen(strncpy(temp_path, get_data_path(), sizeof(temp_path)), sizeof(temp_path));
    size_t pgt_len = strlen(PG_TEMP_FILES_DIR);
    size_t pgt_preff_len = strlen(PG_TEMP_FILE_PREFIX);
    if(len + pgt_len + pgt_preff_len + sizeof(lock_suffix) + 1 < MAXPGPATH)
    {
        temp_path[len] = '/';
        memcpy(temp_path + len + 1, PG_TEMP_FILES_DIR, pgt_len);
#if defined(__linux) || defined(__linux__) || defined(linux)
        struct stat st;
        temp_path[len + pgt_len + 1] = '\x00';
        if (stat(temp_path, &st) == -1)
        {
            if (errno == ENOENT)
            {
                if (mkdir(temp_path, S_IRWXU | S_IRWXG | S_IRWXO) != 0)
                    throw std::runtime_error(std::string("can't create temporary directory: ") + temp_path);
            }
            else
                throw std::runtime_error(std::string("can't check directory presence: ") + temp_path);
        }
        else if(!(st.st_mode & S_IFDIR))
            throw std::runtime_error(std::string("can't use check directory presence: ") + temp_path);
#endif
        temp_path[len + pgt_len + 1] = '/';
        memcpy(temp_path + len + pgt_len + 2, PG_TEMP_FILE_PREFIX, pgt_preff_len);
        memcpy(temp_path + len + pgt_len + pgt_preff_len + 2, lock_suffix, sizeof(lock_suffix));
        int thandle = mkstemp(temp_path);
        if (thandle != -1)
        {
            fchmod(thandle, O_RDWR | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
            close(thandle);

            boost::interprocess::file_lock result(temp_path);
            if(result.try_lock())
            {
                live_lock_name = temp_path;
                return result;
            }
            else
                throw std::runtime_error(std::string("can't lock generated temp file: ") + temp_path);
        }

        throw std::runtime_error(std::string("can't generated temp file by template: ") + get_data_path() +
            '/' + PG_TEMP_FILES_DIR + lock_suffix);
    }

    throw std::runtime_error("can't generated template for temp file");
#endif
}

void remove_old_shared_memory(const boost::interprocess::xsi_key &key, bool ignore_all)
{
    using namespace boost::interprocess;
    try
    {
        xsi_shared_memory xsi(open_only, key);
        xsi_shared_memory::remove(xsi.get_shmid());
    }
    catch(interprocess_exception &e)
    {
        if(!ignore_all && e.get_error_code() != not_found_error)
            throw;
    }
}

void invoke(const void* data, size_t size, const std::function<bool(const void*, size_t)>& func)
{
    if(size > sizeof(commands::Command))
    {
        const commands::Command* command = reinterpret_cast<const commands::Command*>(data);
        switch(command->command_id)
        {
            case 0:
                if(sizeof(commands::MetaByOid) == size)
                {
                    const commands::MetaByOid* __command = static_cast<const commands::MetaByOid*>(command);
                    metaByTableOid(__command->table_oid, func);
                }
                break;

            case 1:
                if(sizeof(commands::MetaByTableName) == size)
                {
                    const commands::MetaByTableName* __command = static_cast<const commands::MetaByTableName*>(command);
                    metaByTableName(__command->table_name, __command->schema_name, func);
                }
                break;

            case 2:
                if(sizeof(commands::FetchByPKOid) == size)
                {
                    const commands::FetchByPKOid* __command = static_cast<const commands::FetchByPKOid*>(command);
                    fetchByKeyTableOid(__command->table_oid, __command->id, __command->use_binary_format, func);
                }
                break;

            case 3:
                if(sizeof(commands::FetchByPKTableName) == size)
                {
                    const commands::FetchByPKTableName* __command = static_cast<const commands::FetchByPKTableName*>(command);
                    fetchByKeyTableName(__command->table_name, __command->schema_name, __command->id, __command->use_binary_format, func);
                }

                break;
        }
    }
}

using Processor = void(*)(const void*, size_t, const std::function<bool(const void*, size_t)>&);

class ParallelRunner
{
public:

    void run()
    {
        std::vector<char> request; request.reserve(4096);
        std::function<bool(const void*, size_t)> writer =
            [&response = exchanger.server_send_buffer] (const void* buffer, size_t size) -> bool {
                return response.write(buffer, size);
            };

        while(!client_terminated)
        {
            if(!exchanger.client_send_buffer.read(request))
                break;

            // пришло задание по "трубе" - значит лочим семафор и работаем "по задаче"
            if(client_terminated)
                break;

            branch_semaphore.wait();
            if(branch_mode == 0)
            {
                // до этой команды был запрос по TCP/IP
                if(IsTransactionState())
                    // нам повезло и транзакция уже открыта - просто фиксируем этот факт и ничего не делаем
                    branch_mode = 2;
                else
                {
                    // нам НЕ повезло и транзакция не открыта - ее нужно открыть, а перед выполнением "обычной" команды закрыть
                    StartTransactionCommand();
                    branch_mode = 1;
                }
            }

            (*processor)(request.data(), request.size(), writer);

            bool is_error = client_terminated || !exchanger.server_send_buffer.flush();

            // освобождаем семафор и только тогда смотрим, не было ли ошибки и выходим, если была
            branch_semaphore.post();

            if(is_error)
                break;

            request.clear();
        }

#if defined(DEBUG_SERVER)
        elog(LOG, "runner finished");
#endif
    }

    ParallelRunner(Processor processor, boost::interprocess::interprocess_semaphore& branch_semaphore, int& branch_mode, const char* lock_path) :
        processor(processor), client_terminated(false), shm_key(calc_key()),
        shm(boost::interprocess::create_only, shm_key, sizeof(Exchanger), unrestricted()),
        region(shm, boost::interprocess::read_write), exchanger(*get_exchanger(region)),
        branch_semaphore(branch_semaphore), branch_mode(branch_mode)
    {
        if(!lock_path || !(*lock_path))
            throw std::runtime_error("client terminate listener file can't be null or empty");

        boost::interprocess::file_lock __terminate_listener(lock_path);

        if (__terminate_listener.try_lock())
            throw std::runtime_error(std::string("client terminate listener file ") + lock_path + " must be locked");
        else
        {
            std::thread([this, terminate_listener = std::move(__terminate_listener),
                         current = boost::posix_time::second_clock::local_time()  + boost::posix_time::hours(1)]() mutable
            {
                for(; !terminate_listener.timed_lock(current); current += boost::posix_time::hours(1))
                    ;

                // на случай, если кто-то еще "висит" на этом же файле, почему бы и нет...
                terminate_listener.unlock();
                client_terminated = true;
                exchanger.client_send_buffer.set_fail();
                exchanger.server_send_buffer.set_fail();
#if defined(DEBUG_SERVER)
                elog(LOG, "client terminated, exchanger got signal to finish");
#endif
            }).detach();
        }
    }

    ~ParallelRunner()
    {
        remove_old_shared_memory(shm_key, true);
        if(client_terminated)
            exchanger.~Exchanger();
    }

    key_t key() const
    {
        return shm_key.get_key();
    }

    void force_finish()
    {
        client_terminated = true;
        exchanger.client_send_buffer.set_fail();
        exchanger.server_send_buffer.set_fail();
    }

private:

    static boost::interprocess::xsi_key calc_key()
    {
#if defined(DEBUG_SERVER)
        boost::interprocess::xsi_key key(872732815);
#else
        boost::interprocess::xsi_key key((std::string(get_data_path()) + '/' + PG_TEMP_FILES_DIR).c_str(), getpid());
#endif
        remove_old_shared_memory(key, false);
        return key;
    }

    static Exchanger* get_exchanger(const boost::interprocess::mapped_region& region)
    {
        return new (region.get_address()) Exchanger{};
    }

    static boost::interprocess::permissions unrestricted()
    {
        boost::interprocess::permissions perm;
        perm.set_unrestricted();
        return perm;
    }

    Processor processor;
    bool client_terminated;
    boost::interprocess::xsi_key shm_key;
    boost::interprocess::xsi_shared_memory shm;
    boost::interprocess::mapped_region region;
    Exchanger& exchanger;
    boost::interprocess::interprocess_semaphore& branch_semaphore;
    int &branch_mode;
};

template<typename R, typename... Args>
class Server
{
public:

    Server(R (*fn)(Args...)) : fn(fn), init_pid(getpid()), branch_mode(0)
    {
        if(!fn)
            throw std::runtime_error("Server must be initialization with wrapped function");
    }

    key_t init(Processor processor, const char* lock_path, std::string& live_lock_name, std::string& error)
    {
        if(!pipe_thread || init_pid != getpid()) // init_pid != getpid() проверяем на случай fork
        {
            try
            {
                branch_semaphore.emplace(0);
                branch_mode = 0;
                // создаем временный залоченный файл для клиента. если он сможет файл заблокировать - значит сервер сдох
                boost::interprocess::file_lock __live_lock(get_locked_temp(live_lock_name));
                if(!__live_lock.try_lock())
                {
                    error = "Can't lock own live_lock file";
                    return -1;
                }

                ParallelRunner* instance = new ParallelRunner(processor, *branch_semaphore, branch_mode, lock_path);
                key_t result = instance->key();

                struct instance_run_checker
                {
                    instance_run_checker(ParallelRunner* instance) : instance(instance), pipe_thread_finish{} {}
                    ~instance_run_checker()
                    {
                        using namespace std::chrono_literals;
                        std::future<bool> future = pipe_thread_finish.get_future();
                        if(future.wait_for(0ms) == std::future_status::ready)
                            future.get();
                        else
                            instance->force_finish();
                    }

                    static void on_exit_program(int, void* run_checker)
                    {
                        delete(reinterpret_cast<instance_run_checker*>(run_checker));
                    }

                    ParallelRunner* instance;
                    std::promise<bool> pipe_thread_finish;
                };

                instance_run_checker* pipe_thread_finisher = new instance_run_checker(instance);
                if(on_exit(instance_run_checker::on_exit_program, pipe_thread_finisher) == 0)
                {
                    pipe_thread = std::async(std::launch::async, [instance, pipe_thread_finisher, live_lock = std::move(__live_lock)]() mutable
                    {
                        instance->run();
#if defined(DEBUG_SERVER)
                        elog(LOG, "pipe thread finished");
#endif
                        pipe_thread_finisher->pipe_thread_finish.set_value(true);
                        delete instance;
                    });

                    init_pid = getpid(); // подтверждаем свое создание в процессе
                }
                else
                {
                    pipe_thread_finisher->pipe_thread_finish.set_value(true);
                    delete pipe_thread_finisher;
                    delete instance;
                    error = "Can't set on_exit listener";
                    return -1;
                }

                return result;
            }
            catch(std::exception& ex)
            {
                error = ex.what();
                branch_semaphore.reset();
                return -1;
            }
        }
        else
        {
            error = "Interconnection already initialized";
            return -1;
        }
    }

    R run(Args&&... args)
    {
        if(pipe_thread && init_pid == getpid()) // init_pid == getpid() проверяем на случай fork
        {
#ifdef PIPE_LIVE_CHECKER
            // Хотя формально, это позволит переинициализировать воркер - в реальности завершение нитки может произойти
            // только в случае "смерти" клиента, а значит больше команд от него не выйдет и постгрес считает завершение
            // потока чтения от команд и завершит процесс.
            struct pipe_live_checker
            {
                pipe_live_checker(std::optional<std::future<void>>& pipe_thread) : pipe_thread(pipe_thread) {}
                ~pipe_live_checker()
                {
                    using namespace std::chrono_literals;
                    static auto zero = 0ms;
                    if (pipe_thread->wait_for(zero) == std::future_status::ready)
                    {
                        pipe_thread.reset();
                        elog(LOG, "pipe_thread was reset");
                    }
                }

                std::optional<std::future<void>>& pipe_thread;
            } checker(pipe_thread);
#endif
            // разрешаем работу параллельному воркеру
            branch_semaphore->post();
            if constexpr (std::is_void_v<R>)
            {
                (*fn)(std::forward<Args>(args)...);
                // это гарантирует нам, что параллельный воркер не станет что-то делать, пока основной процесс работает
                // даже если "основная" функция что-то вернет - она не сможет вернуть значение до тех пор, пока
                // параллельный не разрешит это сделать
                branch_semaphore->wait();

                if(branch_mode == 1)
                {
                    // транзация была открыта в рамках работы pipe.
                    //  чтобы не ломать логику работы TCP/IP соединения - транзакцию следует закрыть
                    AbortCurrentTransaction();
                }
                branch_mode = 0;
            }
            else
            {
                R result = (*fn)(std::forward<Args>(args)...);
                // это гарантирует нам, что параллельный воркер не станет что-то делать, пока основной процесс работает
                // даже если "основная" функция что-то вернет - она не сможет вернуть значение до тех пор, пока
                // параллельный не разрешит это сделать
                branch_semaphore->wait();

                if(branch_mode == 1)
                {
                    // транзация была открыта в рамках работы pipe.
                    //  чтобы не ломать логику работы TCP/IP соединения - транзакцию следует закрыть
                    AbortCurrentTransaction();
                }
                branch_mode = 0;

                return result;
            }
        }
        else
            return (*fn)(std::forward<Args>(args)...);
    }

private:

    R (*fn)(Args...);
    __pid_t init_pid;
    std::optional<std::future<void>> pipe_thread;
    std::optional<boost::interprocess::interprocess_semaphore> branch_semaphore;
    // в какой ветке исполнения находимся:
    // 0 - в TCP/IP
    // 1 - в трубе со своей транзакцией
    // 2 - в трубе с "унаследованной транзакцией
    int branch_mode;
};

Server<int>& wrapper(int (*getbyte_func)())
{
    static Server<int> runner(getbyte_func);
    return runner;
}

}

key_t server_pipe_init(const char* client_lock_path, std::string& live_lock_name, std::string& error)
{
    return wrapper(nullptr).init(invoke, client_lock_path, live_lock_name, error);
}

extern "C" {

int wrap_getbyte(int (*getbyte_func)())
{
    return wrapper(getbyte_func).run();
}

}
