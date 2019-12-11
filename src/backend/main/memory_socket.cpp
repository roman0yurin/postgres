#include <iostream>
#include <string>

extern "C" {

#include "postgres.h"
#include "libpq/libpq-be.h"

extern ssize_t (*secure_read_func)(Port *, void *, size_t);
extern ssize_t (*secure_raw_read_func)(Port *, void *, size_t);
extern ssize_t (*secure_write_func)(Port *, void *, size_t);
extern ssize_t (*secure_raw_write_func)(Port *, const void *, size_t);
extern void (*MarkPostmasterChildActiveFunc)(void);
extern void (*MarkPostmasterChildInactiveFunc)(void);
extern void (*ExceptionalConditionFunc)(const char*, const char*, const char*, int) pg_attribute_noreturn();
void ExceptionalConditionInternal(const char *conditionName, const char *errorType, const char *fileName, int lineNumber) pg_attribute_noreturn();

}

namespace
{

template<size_t buffer_size = 8192>
class RingBuffer
{
public:

    int put(const void *ptr, size_t len)
    {
        size_t limit = buffer_size - cnt;
        if (limit > len) limit = len;
        size_t part = buffer_size - pos;
        if(limit <= part)
        {
            memcpy(buffer + pos, ptr, limit);
            if((pos += limit) == buffer_size)
                pos = 0;
        }
        else
        {
            memcpy(buffer + pos, ptr, part);
            pos = limit - part;
            memcpy(buffer, ((const char *) ptr) + part, pos);
        }

        cnt += limit;
        return limit;
    }

    int get(void *ptr, size_t len)
    {
        if(len > cnt)
            len = cnt;
        if(len == 0)
            return 0;

        size_t begin = cnt > pos? buffer_size + pos - cnt : pos - cnt;
        size_t part = buffer_size - begin;
        if(part >= len)
            memcpy(ptr, buffer + begin, len);
        else
        {
            memcpy(ptr, buffer + begin, part);
            memcpy(((char *) ptr) + part, buffer, len - part);
        }

        cnt -= len;
        return len;
    }

    size_t count() const { return cnt; }
    size_t limit() const { return buffer_size; }
    void   reset() { cnt = pos = 0; }

private:
    size_t pos = 0;
    size_t cnt = 0;
    char buffer[buffer_size];
};

template<size_t decades>
int test_ring(size_t put_size, size_t delta)
{
    const char *obuffer = "12345678901234567890123456789012345678901234567890";
    char ibuffer[128];
    if(put_size > decades * 10)
        return -1;

    constexpr size_t ring_size = decades * 10;
    RingBuffer<ring_size> ring;
    size_t get_size = put_size - delta;
    for(int i = 0, j = 0, _i = 0, _j = 0 ; i + put_size <= ring_size && j < 128 ; i+= (++j, delta))
    {
        if(ring.count() != j * delta)
            return -5;

        if(ring.put(obuffer + _i, put_size) != put_size)
            return -4;

        if(ring.get(ibuffer, get_size) != get_size)
            return -2;

        for(int ii = 0 ; ii < get_size ; ii++)
            if(ibuffer[ii] != obuffer[_j + ii])
                return -3;

        _i += put_size;
        _i %= 10;
        _j += get_size;
        _j %= 10;
    }

    return 0;
}

static RingBuffer<16384> for_recv;
static RingBuffer<16384> for_send;

ssize_t memory_read(Port *, void *ptr, size_t len)
{
    return for_recv.get(ptr, len);
}

ssize_t memory_raw_read(Port *, void *ptr, size_t len)
{
    return for_recv.get(ptr, len);
}

ssize_t memory_write(Port *, void *ptr, size_t len)
{
    return for_send.put(ptr, len);
}

ssize_t memory_raw_write(Port *, const void *ptr, size_t len)
{
    return for_send.put(ptr, len);
}

void
MarkPostmasterChildStub(void)
{
}

void
CppExceptionalConditionReThrower(const char *conditionName, const char *errorType, const char *fileName, int lineNumber) pg_attribute_noreturn();

void
CppExceptionalConditionReThrower(const char *conditionName, const char *errorType, const char *fileName, int lineNumber)
{
    char error[4096];
    if (!PointerIsValid(conditionName)
        || !PointerIsValid(fileName)
        || !PointerIsValid(errorType))
        snprintf(error, sizeof(error), "TRAP: ExceptionalCondition: bad arguments");
    else
    {
        snprintf(error, sizeof(error), "TRAP: %s(\"%s\", File: \"%s\", Line: %d)",
                     errorType, conditionName,
                     fileName, lineNumber);
    }

    ExceptionalConditionFunc = &ExceptionalConditionInternal;
    throw std::runtime_error(error);
}

}

extern "C" {

void setup_memory_socket()
{
    secure_read_func = memory_read;
    secure_raw_read_func = memory_raw_read;
    secure_write_func = memory_write;
    secure_raw_write_func = memory_raw_write;

#ifdef TEST_MEMORY_SOCKET
    char buffer[128];
    std::string line("Hello world! How are you? I'm fine");
    std::string line("12345678901234567890123456789012345678901234567890");
    RingBuffer<16> test;
    std::cout << test.get(buffer, sizeof(buffer)) << std::endl;
    std::cout << test.put(line.c_str(), line.length()) << std::endl;
    std::cout << std::string(buffer, test.get(buffer, sizeof(buffer))) << std::endl;
    std::cout << test.put(line.c_str(), line.length()) << std::endl;
    std::cout << std::string(buffer, test.get(buffer, 13)) << std::endl;
    std::cout << test.put(line.c_str(), 7) << std::endl;
    std::cout << std::string(buffer, test.get(buffer, 13)) << std::endl;
    std::cout << test.put(line.c_str(), 7) << std::endl;
    std::cout << std::string(buffer, test.get(buffer, 13)) << std::endl;
    std::cout << test.put(line.c_str(), 13) << std::endl;
    std::cout << std::string(buffer, test.get(buffer, 10)) << std::endl;
    std::cout << test.put(line.c_str(), 13) << std::endl;
    std::cout << std::string(buffer, test.get(buffer, 10)) << std::endl;

    std::cout << "test_ring<> - " << test_ring<2>(8, 1) << std::endl;
    std::cout << "test_ring<> - " << test_ring<2>(9, 1) << std::endl;
    std::cout << "test_ring<> - " << test_ring<2>(9, 2) << std::endl;
    std::cout << "test_ring<> - " << test_ring<2>(10, 3) << std::endl;
    std::cout << "test_ring<> - " << test_ring<2>(13, 2) << std::endl;
    std::cout << "test_ring<> - " << test_ring<2>(15, 0) << std::endl;
    std::cout << "test_ring<> - " << test_ring<2>(15, 3) << std::endl;
#endif
}

int put_for_recv(const void *ptr, size_t len)
{
    return for_recv.put(ptr, len);
}

int get_from_send(void *ptr, size_t len)
{
    return for_send.get(ptr, len);
}

void SetupMarkPostmasterChildInternal()
{
    MarkPostmasterChildActiveFunc = MarkPostmasterChildStub;
    MarkPostmasterChildInactiveFunc = MarkPostmasterChildStub;
}

void SetupCppExceptionalConditionReThrower()
{
    ExceptionalConditionFunc = &CppExceptionalConditionReThrower;
}

void RestoreExceptionalCondition()
{
    ExceptionalConditionFunc = &ExceptionalConditionInternal;
}

void ThrowCppException(const char* message) pg_attribute_noreturn();

void ThrowCppException(const char* message)
{
    throw std::runtime_error(message);
}

}