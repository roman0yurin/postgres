//#define DEBUG_CLIENT

#if defined(DEBUG_SERVER) || defined(DEBUG_CLIENT)
#include <iostream>
#endif
#include "cmake.h"
#include <string>
#include <thread>
#ifndef IS_ASTRA
    #include <optional>
#else
    #include <experimental/optional>
#endif
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


namespace
{

static std::pair<std::string, boost::interprocess::file_lock> check_lock_file_name(const char* lock_file_name)
{
    if(lock_file_name && *lock_file_name)
    {
        boost::interprocess::file_lock lock(lock_file_name);
        if(!lock.try_lock())
            throw std::runtime_error(std::string("can't use for unique lock file: ") + lock_file_name);

        return std::pair<std::string, boost::interprocess::file_lock>(std::string(lock_file_name), std::move(lock));
    }
    else
    {
        static const char common_temp_template[] = "/tmp/client_live_lock_XXXXXX";
        char temp_path[1024];
        memcpy(temp_path, common_temp_template, sizeof(common_temp_template));
        int thandle = mkstemp(temp_path);
        if (thandle != -1)
        {
            fchmod(thandle, O_RDWR | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
            close(thandle);

            boost::interprocess::file_lock lock(temp_path);
            if(lock.try_lock())
            {
                return std::pair<std::string, boost::interprocess::file_lock>(std::string(temp_path), std::move(lock));
            }
            else
                throw std::runtime_error(std::string("can't lock generated temp file: ") + temp_path);
        }

        throw std::runtime_error(std::string("can't generated temp file by template: ") + common_temp_template);
    }
}

static std::pair<std::string, boost::interprocess::file_lock>& obtain_lock(const char* lock_file_name = nullptr)
{
    static std::pair<std::string, boost::interprocess::file_lock> file_lock(check_lock_file_name(lock_file_name));
    return file_lock;
}

class Client
{
public:

    Client(const char* lock_file_name = nullptr) : server_terminated(false), guard(1), exchanger(nullptr)
    {
        obtain_lock(lock_file_name);
    }

    Client(Client&& ) = delete;
    Client(const Client&) = delete;

    ~Client()
    {
        if(!server_terminated)
            shell.set_value(true);
    }

#ifndef IS_ASTRA
    bool connect(const char* server_lock_filename, key_t shm_key_id, std::string& error)
    {
        SemaphoreGuard __guard(guard);
        if(shm.get_shmid() == -1)
        {
            using namespace boost::interprocess;
            file_lock __terminate_listener(server_lock_filename);
            if (__terminate_listener.try_lock())
            {
                error = std::string("server terminate listener file ") + server_lock_filename + " must be locked";
                return false;
            }
            else
            {
                try
                {
                    shm = xsi_shared_memory(open_only, xsi_key(shm_key_id));
                    if(shm.get_shmid() == -1)
                    {
                        error = std::string("server xsi shared memory with id: ") + std::to_string(shm_key_id) + " wasn't open";
                        return false;
                    }

                    region = mapped_region(shm, read_write);
                    exchanger = static_cast<Exchanger*>(region.get_address());

                    std::thread([this, terminate_listener = std::move(__terminate_listener),
                                    current = boost::posix_time::second_clock::local_time()  + boost::posix_time::hours(1),
                                    shell = shell.get_future()]() mutable
                    {
                        for(; !terminate_listener.timed_lock(current); current += boost::posix_time::hours(1))
                            ;

                        // на случай, если кто-то еще "висит" на этом же файле, в ожидании освобождения, то почему бы и нет...
                        terminate_listener.unlock();
                        {
                            using namespace std::chrono_literals;
                            if (shell.wait_for(0ms) == std::future_status::ready)
                            {
                                // оболочки уже нет, а листенер сработал - сообщать некому
#if defined(DEBUG_CLIENT)
                                            std::cout << "shell already destroyed... not signaling" << std::endl;
#endif
                            }
                            else
                            {
                                server_terminated.store(true);
                                exchanger->client_send_buffer.set_fail();
                                exchanger->server_send_buffer.set_fail();
                                if(guard.try_wait())
                                {
                                    clear_exchanger();
                                    guard.post();
                                }
#if defined(DEBUG_CLIENT)
                                std::cout << "signaling shell that server terminated" << std::endl;
#endif
                            }
                        }
                    }).detach();

                    return true;
                }
                catch(std::exception& ex)
                {
                    if(shm.get_shmid() != -1) shm = xsi_shared_memory();
                    error = ex.what();
                    return false;
                }
            }
        }
        else
        {
            error = "Interconnection already initialized";
            return -1;
        }
    }
#else
    bool connect(const char* server_lock_filename, key_t shm_key_id, std::string& error){
        //throw "NOT SUPPORTED IN ASTRA -> bool connect(const char* server_lock_filename, key_t shm_key_id, std::string& error)";
    }
#endif

    bool invoke(const void* request, size_t size, std::vector<char>& response)
    {
        if (!exchanger)
            return false;

        SemaphoreGuard __guard(guard);
        if(server_terminated)
            return clear_exchanger();

        if (!exchanger->client_send_buffer.write(request, size) || !exchanger->client_send_buffer.flush() ||
            !exchanger->server_send_buffer.read(response))
            return clear_exchanger();

        return true;
    }

private:

    bool clear_exchanger()
    {
        std::call_once(clear_flag, [this]()
        {
            if(exchanger)
            {
                if(server_terminated)
                    exchanger->~Exchanger();
                exchanger = nullptr;
            }
        });
        return false;
    }

    class SemaphoreGuard
    {
    public:
        SemaphoreGuard(boost::interprocess::interprocess_semaphore& semaphore) : semaphore(semaphore) { semaphore.wait(); }
        ~SemaphoreGuard() { semaphore.post(); }

    private:
        boost::interprocess::interprocess_semaphore& semaphore;
    };

    std::atomic<bool> server_terminated;
    boost::interprocess::interprocess_semaphore guard;
    boost::interprocess::xsi_shared_memory shm;
    boost::interprocess::mapped_region region;
    std::promise<bool> shell;
    Exchanger* exchanger;
    std::once_flag clear_flag;
};

}

const std::string& lock_file_name()
{
    return obtain_lock().first;
}

namespace
{

class ClientWrapperImpl : public ClientWrapper
{
public:
    ClientWrapperImpl();
    bool invoke(const void* request, size_t size, std::vector<char>& response) override;
    void connect(const char* server_lock_filename, key_t shm_key_id);
private:
    Client client;
};

ClientWrapperImpl::ClientWrapperImpl() : client(lock_file_name().c_str())
{
}

bool ClientWrapperImpl::invoke(const void* request, size_t size, std::vector<char>& response)
{
    return client.invoke(request, size, response);
}

void ClientWrapperImpl::connect(const char* server_lock_filename, key_t shm_key_id)
{
    std::string error;
    if(!client.connect(server_lock_filename, shm_key_id, error))
        throw std::runtime_error(error);
}

std::unordered_map<key_t, std::shared_ptr<ClientWrapperImpl>>& client_storage()
{
    static std::unordered_map<key_t, std::shared_ptr<ClientWrapperImpl>> storage;
    return storage;
}

}

std::shared_ptr<ClientWrapper> connect(const char* server_lock_filename, key_t shm_key_id)
{
    static std::mutex client_storage_mutex{};
    std::lock_guard<std::mutex> guard(client_storage_mutex);
    std::unordered_map<key_t, std::shared_ptr<ClientWrapperImpl>>& storage = client_storage();
    auto it = storage.find(shm_key_id);
    if(it == storage.end())
    {
        std::shared_ptr<ClientWrapperImpl> new_client = std::make_shared<ClientWrapperImpl>();
        new_client->connect(server_lock_filename, shm_key_id);
        return storage.emplace(std::pair(std::move(shm_key_id), std::move(new_client))).first->second;
    }
    else
        throw std::runtime_error(std::string("connection with shm_key_id: ") + std::to_string(shm_key_id) + " already established");
}
