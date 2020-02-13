#include "exchange_buffer.hpp"

template<size_t buffer_size>
void ExchangeBuffer<buffer_size>::set_fail()
{
    fail_state = true;
    buffer_free.post();
    buffer_filled.post();
}

template<size_t buffer_size>
bool ExchangeBuffer<buffer_size>::write(const void *buffer, size_t size)
{
    int offset = 0;
    while(size)
    {
        buffer_free.wait();
        if (fail_state) { buffer_free.post(); return false; }

        write_finish = false;

        if (pos + size >= buffer_size)
        {
            size_t written = buffer_size - pos;
            memmove(exchange_buffer + pos, static_cast<const char*>(buffer) + offset, written);

            size -= written;
            offset += written;
            pos = buffer_size;

            buffer_filled.post();
        }
        else
        {
            memmove(exchange_buffer + pos, static_cast<const char*>(buffer) + offset, size);
            pos += size;
            buffer_free.post();

            return true;
        }
    }

    return true;
}

template<size_t buffer_size>
bool ExchangeBuffer<buffer_size>::read(std::vector<char>& dest)
{
    bool is_finish;
    do
    {
        if (fail_state)
            return false;

        buffer_filled.wait();
        if (fail_state) { buffer_filled.post(); return false; }

        if((is_finish = write_finish) == true)
            write_finish = false;

        if(pos > 0)
        {
            dest.insert(dest.end(), exchange_buffer, exchange_buffer + pos);
            pos = 0;
        }

        buffer_free.post();
    }
    while(!is_finish);

    return true;
}

template<size_t buffer_size>
bool ExchangeBuffer<buffer_size>::flush()
{
    buffer_free.wait();
    if (fail_state) { buffer_free.post(); return false; }

    write_finish = true;
    buffer_filled.post();

    return true;
}

template class ExchangeBuffer<1024>;
template class ExchangeBuffer<16384>;
