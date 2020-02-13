#ifndef EXCHANGE_BUFFER_HPP
#define EXCHANGE_BUFFER_HPP

#include <boost/interprocess/sync/interprocess_semaphore.hpp>

template<size_t buffer_size>
class ExchangeBuffer
{
public:

    void set_fail();

    bool write(const void *buffer, size_t size);

    bool read(std::vector<char>& dest);

    bool flush();

private:
    volatile size_t pos = 0;
    boost::interprocess::interprocess_semaphore buffer_free{1}, buffer_filled{0};
    volatile bool fail_state = false;
    volatile bool write_finish = false;
    char exchange_buffer[buffer_size];
};

struct Exchanger
{
    ExchangeBuffer<1024> client_send_buffer;
    ExchangeBuffer<16384> server_send_buffer;
};

#endif