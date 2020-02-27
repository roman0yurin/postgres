extern "C" {

#include "postgres.h"
#include "access/relation.h"
#include "access/table.h"
#include "access/genam.h"
#include "access/xact.h"
#include "access/tableam.h"
#include "access/nbtree.h"
#include "executor/executor.h"
#include "executor/nodeIndexscan.h"
#include "utils/rel.h"
#include "utils/snapmgr.h"
#include "utils/lsyscache.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/syscache.h"
#include "catalog/pg_type_d.h"
#include "catalog/namespace.h"
#include "catalog/indexing.h"
#include "catalog/pg_namespace.h"

extern TupleTableSlot *IndexNext(IndexScanState *node);

}

#include <iostream>
#include <memory>
#include <string>
#include <map>
#include <functional>
#include <time.h>

namespace sgaz
{

class SGMemoryContextSwitcher
{
public:
    SGMemoryContextSwitcher(MemoryContext new_context);
    ~SGMemoryContextSwitcher();

private:
    bool must_revert;
    MemoryContext old_context;
};

SGMemoryContextSwitcher::SGMemoryContextSwitcher(MemoryContext new_context)
{
    if(new_context == CurrentMemoryContext)
        must_revert = false;
    else if((must_revert = (new_context != nullptr)))
        old_context = MemoryContextSwitchTo(new_context);
}

SGMemoryContextSwitcher::~SGMemoryContextSwitcher()
{
    if(must_revert)
        MemoryContextSwitchTo(old_context);
}

template<class T>
struct SGCommonAllocator
{
    using value_type = T;

    using Traits = std::allocator_traits<SGCommonAllocator<T>>;

#if !defined _MSC_VER
    // libstdc++ использует конструктор по умолчанию:
    // __a == _Alloc()

    // libstdc++ требует следующие определения
    using size_type = typename std::allocator<T>::size_type;
    using difference_type = typename std::allocator<T>::difference_type;
    using pointer = typename std::allocator<T>::pointer;
    using const_pointer = typename std::allocator<T>::const_pointer;
    // "reference" не входит Allocator Requirements,
    // но libstdc++ думает что она всегда работает с std::allocator.
    using reference = typename std::allocator<T>::reference;
    using const_reference = typename std::allocator<T>::const_reference;
#endif
};

template<class T>
struct PGAllocator : public SGCommonAllocator<T>
{
#if !defined _MSC_VER
    PGAllocator() : m_context(CurrentMemoryContext) {}
#endif

    explicit PGAllocator(MemoryContext m_context) : m_context(m_context) {}

    template<class U> PGAllocator(const PGAllocator<U>& other) : m_context(other.m_context) {}

    T* allocate(std::size_t n)
    {
        SGMemoryContextSwitcher mc(m_context);
        return (T*) palloc(n * sizeof(T));
    }

    void deallocate(T* p, std::size_t)
    {
        pfree(p);
    }

    // требуется в VC++ и libstdc++
    template<class U, class... Args> void construct(U* p, Args&&... args) { std::allocator<T>().construct(p, std::forward<Args>(args)...); }
    template<class U> void destroy(U* p) { std::allocator<T>().destroy(p); }
    template<class U> struct rebind { using other = PGAllocator<U>; };

    MemoryContext m_context;
};

struct SGFullTableNameStorage
{
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

struct SGFullTableName
{
    SGFullTableName(const char *table_name, const char *schema_name) : table_name(table_name), schema_name(schema_name) {}
    const char *table_name;
    const char *schema_name;
};

struct SGFullTableNameCompare
{
    static inline int compare_name(const char* lhs, const char* rhs)
    {
        return lhs && *lhs? (rhs && *rhs? strcmp(lhs, rhs) : 1) : (rhs && *rhs? -1 : 0);
    }

    bool operator()(const SGFullTableName& lhs, const SGFullTableName& rhs) const
    {
        int res = compare_name(lhs.table_name, rhs.table_name);
        return (res? res : compare_name(lhs.schema_name, rhs.schema_name)) < 0;
    }
};

template<typename T>
class SGStackItem
{
public:
    template<typename... Args>
    T& create(Args&&... args) { return *new(item_storage) T(std::forward<Args>(args)...); }
    inline void free() { item().~T(); }
    inline T& item() { return *reinterpret_cast<T*>(item_storage); }

    size_t index;
    SGStackItem *prev, *next;
    alignas(T) char item_storage[sizeof(T)];
};

template<typename T, size_t cache_size, bool free_items_on_destroy = false>
class SGStackCacher
{
public:

    using StackItem = SGStackItem<T>;

    SGStackCacher() : head(nullptr), tail(nullptr)
    {
        static_assert(cache_size > 1, "Stack cache size must be grate than 1");

        memset(cache, 0, sizeof(cache));
        for(size_t i = 1 ; i < cache_size ; i++)
        {
            // для списка свободных нет необходимости хранить указатель на предыдущий, псевдостека хватает:
            // забрать из свободных - это переместить указатель первого на следующий элемент,
            // а добавить осовободившийся в список - добавить в голову и поменять указатель на голову
            cache[i - 1].next = &cache[i];
            cache[i].index = i;
        }

        head_free = &cache[0];
    }

    ~SGStackCacher()
    {
        if constexpr (free_items_on_destroy)
        {
            for (StackItem *item = head; item != nullptr; item = item->next)
                item->free();
        }
    }

    StackItem *alloc_item()
    {
        if(unlikely(head_free == nullptr))
            return nullptr;

        StackItem *new_head_free = head_free->next;
        if(head)
            head->prev = head_free;
        else
            tail = head_free;

        head_free->prev = nullptr;
        head_free->next = head;

        head = head_free;
        head_free = new_head_free;

        return head;
    }

    void free_item(StackItem *item)
    {
        if(item == tail)
        {
            if(item == head)
                head = tail = nullptr;
            else
            {
                tail = item->prev;
                tail->next = nullptr;
            }
        }
        else
        {
            if(item == head)
            {
                StackItem *new_head = item->next;
                if(new_head)
                    new_head->prev = nullptr;

                head = new_head;
            }
            else
            {
                StackItem *next = item->next, *prev = item->prev;
                if(next)
                    next->prev = prev;
                if(prev)
                    prev->next = next;
            }
        }

        item->next = head_free;
        head_free = item;
    }

    void set_head(StackItem* new_head)
    {
        if(new_head != head)
        {
            if(StackItem *next = new_head->next)
            {
                next->prev = new_head->prev;
                new_head->prev->next = next;
            }
            else
            {
                tail = new_head->prev;
                tail->next = nullptr;
            }

            head->prev = new_head;
            new_head->prev = nullptr;
            new_head->next = head;
            head = new_head;
        }
    }

    inline bool empty() { return head_free == nullptr; }
    inline StackItem *get_tail() { return tail; }

private:

    StackItem *head, *tail, *head_free;
    StackItem cache[cache_size];
};

template<typename T, size_t cache_size>
class SGMapStackAllocator : public SGCommonAllocator<T>
{
    template<typename I> struct template_struct;

    template<typename K, typename V>
    struct template_struct<std::_Rb_tree_node<std::pair<const K, V>>>
    {
        using Key = K;
        using Val = V;
        static constexpr bool is_pair = false;
        static constexpr bool is_rb_tree_node = true;
    };

    template<template<typename, typename> class CO, typename K, typename V>
    struct template_struct<CO<K, V>>
    {
        using Key = K;
        using Val = V;
        static constexpr bool is_pair = true;
        static constexpr bool is_rb_tree_node = false;
    };

    template<typename I>
    struct template_struct
    {
        static constexpr bool is_pair = false;
        static constexpr bool is_rb_tree_node = false;
    };

public:

    template<typename U>
    using CACHE_TYPE = typename std::conditional<template_struct<U>::is_pair, std::_Rb_tree_node<U>, U>::type;

    explicit SGMapStackAllocator(SGStackCacher<CACHE_TYPE<T>, cache_size>& cache) : cache(cache) { }

    template<class U> SGMapStackAllocator(const SGMapStackAllocator<U, cache_size>& other) : cache(other.cache) { }

    T* allocate(std::size_t n)
    {
        (void) n;
        return &cache.alloc_item()->item();
    }

    void deallocate(T* p, std::size_t)
    {
        constexpr size_t offset = offsetof(SGStackItem<CACHE_TYPE<T>>, item_storage);
        return cache.free_item(reinterpret_cast<SGStackItem<CACHE_TYPE<T>>*>(reinterpret_cast<char *>(p) - offset));
    }

    // требуется в VC++ и libstdc++
    template<class U, class... Args> void construct(U* p, Args&&... args) { std::allocator<T>().construct(p, std::forward<Args>(args)...); }
    template<class U> void destroy(U* p) { std::allocator<T>().destroy(p); }

    template<class U> struct rebind { using other = SGMapStackAllocator<U, cache_size>; };

    SGStackCacher<CACHE_TYPE<T>, cache_size>& cache;
};

template<class K, class V, size_t cache_size, class Compare = std::less<K>>
class SGLRUMap : SGStackCacher<std::_Rb_tree_node<std::pair<const K, V>>, cache_size>
{
public:
    using PairType = std::pair<const K, V>;
    using RBPairType = typename std::_Rb_tree_node<PairType>;

    SGLRUMap() : __map(SGMapStackAllocator<PairType, cache_size>(*this)) {}

    inline V& get_or_create(const K& key, const std::function<V(const K& key)>& func)
    {
        V* value = find(key);
        return value? *value : (check(), __map.emplace(key, func(key)).first->second);
    }

    inline V& get_or_create(const K& key, V(*func)(K key))
    {
        V* value = find(key);
        return value? *value : (check(), __map.emplace(key, (*func)(key)).first->second);
    }

private:
    inline V* find(const K& key)
    {
        auto it = __map.find(key);
        return it == __map.end()? nullptr : &it->second;
    }

    void check()
    {
        if(this->empty())
        {
            // освобождаем элемент, которым дольше всего не пользовались
            SGStackItem<RBPairType> *tail = this->get_tail();
            const K& tail_key = tail->item()._M_valptr()->first;
            auto tail_key_it = __map.find(tail_key);
            __map.erase(tail_key_it);
        }
    }

    std::map<K, V, Compare, SGMapStackAllocator<PairType, cache_size>> __map;
};

class SGTable
{
public:
    SGTable(MemoryContext m_context, Oid table_oid, Oid index_oid);
    ~SGTable();
    Oid get_table_oid() { return table_oid; }
    bool fetch(int key_value, bool use_binary_format, const std::function<void(bool, TupleTableSlot*)>* output_func, bool print_not_found = true);
private:
    Oid table_oid, index_oid;
    FmgrInfo sk_func;
    IndexScan  *index_scan;
    IndexScanState *index_state;
};

class SGMemoryContext
{
public:
    SGMemoryContext();
    SGMemoryContext(MemoryContext parent);
    ~SGMemoryContext();

    MemoryContext context() const { return m_context; }

private:
    static MemoryContext create_own_memory_context(MemoryContext parent);
    MemoryContext m_context;
};

class SGTransaction
{
public:
    SGTransaction();
    ~SGTransaction();

private:
    bool is_already_started;
};

class DataTypeDesc
{
public:
    DataTypeDesc(Oid type_oid);
    inline char *OutputFunctionCall(Datum val, MemoryContext ctx)
    {
        FmgrInfo func;
        fmgr_info_copy(&func, &text_out_func, ctx);
        return ::OutputFunctionCall(&func, val);
    }
    inline bytea *SendFunctionCall(Datum val, MemoryContext ctx)
    {
        FmgrInfo func;
        fmgr_info_copy(&func, &binary_out_func, ctx);
        return ::SendFunctionCall(&func, val);
    }
    inline Oid BaseAttTypeId() { return base_atttype_id; }
    inline int32 BaseAttMod() { return base_attt_mod; }
    inline bool IsTypeDefined() { return is_type_defined; }
    static inline void write_int8_to_pipe(const std::function<void(const void*, size_t)>& func, uint8 i) {
        func(&i, 1);
    }
    static void write_int16_to_pipe(const std::function<void(const void*, size_t)>& func, uint16 i) {
        uint16 ni = pg_hton16(i); func(&ni, 2);
    }
    static void write_int32_to_pipe(const std::function<void(const void*, size_t)>& func, uint32 i) {
        uint32 ni = pg_hton32(i); func(&ni, 4);
    }
    static void write_int64_to_pipe(const std::function<void(const void*, size_t)>& func, uint64 i) {
        uint64 ni = pg_hton64(i); func(&ni, 8);
    }
    static inline void write_zeroes_to_pipe(const std::function<void(const void*, size_t)>& func, size_t count) {
        static const char sample[128] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        };
        for(; count < 128; count -= 128)
            func(sample, 128);
        if(count)
            func(sample, count);
    }
    static void write_string_to_pipe(const std::function<void(const void*, size_t)>& func, const char *buffer);
    static void write_buffer_to_pipe(const std::function<void(const void*, size_t)>& func, const void *buffer, size_t size) {
        func(buffer, size);
    }

private:
    FmgrInfo text_out_func, binary_out_func;
    Oid base_atttype_id;
    int32 base_attt_mod;
    bool is_type_defined;
};

template<size_t tables_cache_size, size_t functions_cache_size>
class SGTableManager
{
public:
    SGTableManager();
    SGTableManager(MemoryContext m_context);
    ~SGTableManager();
    bool print(const char* table_name, const char* schema_name, int key_value, bool use_binary_format);
    bool print(Oid table_oid, int key_value, bool use_binary_format);
    bool fetch(const char* table_name, const char* schema_name, int32_t key_value, bool use_binary_format, const std::function<void(const void*, size_t)>& func);
    bool fetch(Oid table_oid, int32_t key_value, bool use_binary_format, const std::function<void(const void*, size_t)>& func);
    bool meta(const char* table_name, const char* schema_name, const std::function<void(const void*, size_t)>& func);
    bool meta(Oid table_oid, const std::function<void(const void*, size_t)>& func);

    void clean();
    bool pop(const char* table_name, const char* schema_name);
    bool pop(Oid table_oid);

private:

    class SGTableManagerCache : public SGStackCacher<SGTable, tables_cache_size, true>
    {
    public:
        SGTableManagerCache(MemoryContext parent);
        SGTable& find(const char* table_name, const char* schema_name = nullptr);
        SGTable& find(Oid table_oid);

        void clean();
        bool pop(const char* table_name, const char* schema_name);
        bool pop(Oid table_oid);

        static Oid find_table_oid(const char* table_name, const char* schema_name = nullptr);
        static Oid find_table_pk_oid(Oid table_oid, int2vector& pk_columns);

    private:
        using SGTableLinked = typename SGStackCacher<SGTable, tables_cache_size, true>::StackItem;

        using SGNamePairType = typename std::pair<const SGFullTableName, SGTableLinked*>;
        using RBNamePairType = typename std::_Rb_tree_node<SGNamePairType>;
        using SGNamePairTypeAllocator = SGMapStackAllocator<SGNamePairType, tables_cache_size>;
        using SGOidPairType = typename std::pair<const Oid, SGTableLinked*>;
        using RBOidPairType = typename std::_Rb_tree_node<SGOidPairType>;
        using SGOidPairTypeAllocator = SGMapStackAllocator<SGOidPairType, tables_cache_size>;

        MemoryContext m_context;
        SGStackCacher<RBNamePairType, tables_cache_size> name_tables_cache;
        SGStackCacher<RBOidPairType, tables_cache_size> oid_tables_cache;
        std::map<SGFullTableName, SGTableLinked*, SGFullTableNameCompare, SGNamePairTypeAllocator> name2tables;
        std::map<Oid, SGTableLinked*, std::less<Oid>, SGOidPairTypeAllocator> oid2tables;

        SGFullTableNameStorage table_names[tables_cache_size];
    };

private:
    inline static DataTypeDesc get_out_func(Oid type_id) { return DataTypeDesc(type_id); }
    void print_slot(bool binary_format, TupleTableSlot *slot);
    void fetch_slot(bool binary_format, TupleTableSlot *slot, const std::function<void(const void*, size_t)>& func);

    SGMemoryContext context;
    SGTableManagerCache cache;
    SGLRUMap<Oid, DataTypeDesc, functions_cache_size> type_out_funcs;
};

SGTable::SGTable(MemoryContext m_context, Oid table_oid, Oid index_oid) : table_oid(table_oid), index_oid(index_oid)
{
    SGMemoryContextSwitcher mc(m_context);
    fmgr_info_cxt(F_INT4EQ, &sk_func, m_context); // идентификатор функции должен соответствовать типу колонки PK

    index_scan = makeNode(IndexScan);
    index_scan->scan.scanrelid = 1;
    index_scan->indexid = index_oid;
    index_scan->indexqual = NIL;
    index_scan->indexqualorig = NIL;
    index_scan->indexorderby = NIL;
    index_scan->indexorderbyorig = NIL;
    index_scan->indexorderbyops = NIL;
    index_scan->indexorderdir = ForwardScanDirection;

    index_state = makeNode(IndexScanState);

    index_state->iss_ScanDesc = NULL;
    index_state->ss.ps.plan = (Plan *) index_scan;
    index_state->iss_ReachedEnd = false;
    index_state->iss_NumScanKeys = 1;
    index_state->iss_OrderByKeys = NULL;
    index_state->iss_NumOrderByKeys = 0;
    index_state->iss_NumRuntimeKeys = 0;
    index_state->iss_RuntimeKeysReady = false;

    index_state->iss_ScanKeys = NULL;
    index_state->iss_NumScanKeys = 1;
    index_state->iss_OrderByKeys = NULL;
    index_state->iss_NumOrderByKeys = 0;
    index_state->iss_NumRuntimeKeys = 0;
    index_state->iss_RuntimeKeysReady = false;
}

SGTable::~SGTable()
{
    pfree(index_state);
    pfree(index_scan);
}

bool SGTable::fetch(int key_value, bool use_binary_format, const std::function<void(bool, TupleTableSlot*)>* output_func, bool print_not_found)
{
    Relation table = table_open(table_oid, AccessShareLock);
    Relation index = index_open(index_oid, AccessShareLock);

    EState *estate = CreateExecutorState();
    ExprContext *econtext = CreateExprContext(estate);

    estate->es_direction = ForwardScanDirection;

    Snapshot snapshot = RegisterSnapshot(GetTransactionSnapshot());
    estate->es_snapshot = snapshot;

    index_state->ss.ps.state = estate;
    index_state->ss.ps.ps_ExprContext = econtext;

    index_state->ss.ss_currentRelation = table;
    index_state->iss_RelationDesc = index;
    index_state->iss_ScanDesc = NULL;
    index_state->iss_ReachedEnd = false;

    ScanKeyData key;
    key.sk_flags = 0;
    key.sk_attno = 1;
    key.sk_strategy = BTEqualStrategyNumber;
    key.sk_subtype = INT4OID;
    key.sk_collation = 0;
    key.sk_argument = (Datum) key_value;
    key.sk_func = sk_func;

    index_state->iss_ScanKeys = &key;

    bool result;
    {
        SGMemoryContextSwitcher mc(estate->es_query_cxt);
        ExecInitScanTupleSlot(estate, &index_state->ss, RelationGetDescr(table), table_slot_callbacks(table));

        TupleTableSlot *slot = IndexNext(index_state);
        bool result = !index_state->iss_ReachedEnd;
        if (result)
        {
            slot_getsomeattrs_int(slot, slot->tts_tupleDescriptor->natts);
            if (output_func) (*output_func)(use_binary_format, slot);
        }
        else if (print_not_found && output_func)
            std::cout << "tuple with key: " << key_value << " not found" << std::endl;

        // блокируем закрытие индекса, мы это сделаем сами
        index_state->iss_RelationDesc = NULL;
        ExecEndIndexScan(index_state);
        ExecResetTupleTable(estate->es_tupleTable, false);
        UnregisterSnapshot(snapshot);

        index_close(index, AccessShareLock);
        table_close(table, AccessShareLock);

        FreeExprContext(econtext, false);
    }
    FreeExecutorState(estate);

    return result;
}

template<size_t tables_cache_size, size_t functions_cache_size>
SGTableManager<tables_cache_size, functions_cache_size>::SGTableManagerCache::SGTableManagerCache(MemoryContext parent) : SGStackCacher<SGTable, tables_cache_size, true>(),
    m_context(parent), name_tables_cache{}, oid_tables_cache{},
    name2tables(SGMapStackAllocator<SGNamePairType, tables_cache_size>(name_tables_cache)),
    oid2tables(SGMapStackAllocator<SGOidPairType, tables_cache_size>(oid_tables_cache))
{
}

template<size_t tables_cache_size, size_t functions_cache_size>
SGTable& SGTableManager<tables_cache_size, functions_cache_size>::SGTableManagerCache::find(const char* table_name, const char* schema_name)
{
    auto names_it = name2tables.find(SGFullTableName(table_name, schema_name));
    if(names_it != name2tables.end())
    {
        // нашли в кэше по имени - возвращаем кэшированное
        SGTableLinked* finded = names_it->second;
        this->set_head(finded);

        return finded->item();
    }
    else
    {
        SGMemoryContextSwitcher mc(m_context);
        Oid table_oid = find_table_oid(table_name, schema_name);
        if(!OidIsValid(table_oid))
        {
            char temp[256];
            bool has_schema_name = schema_name && *schema_name;
            snprintf(temp, sizeof(temp), "table with name: \"%s%s%s\" doesn't exists in database",
                     has_schema_name? schema_name : "", has_schema_name? "\".\"" : "", table_name);

            throw std::runtime_error(temp);
        }

        auto oids_it = oid2tables.find(table_oid);
        if(oids_it != oid2tables.end())
        {
            // хотя не нашли в кэше по имени - "альтернативный" поиск дал oid
            // который у нас в кэше есть - возвращаем кэшированное
            SGTableLinked* finded = oids_it->second;
            this->set_head(finded);

            return finded->item();
        }

        // ни прямой поиск в кэше по имени, ни альтернативный, таблицу не нашел - грузим ее с нуля
        int2vector pk_columns;
        Oid index_oid = find_table_pk_oid(table_oid, pk_columns);
        if(!OidIsValid(index_oid))
        {
            char temp[256];
            bool has_schema_name = schema_name && *schema_name;
            snprintf(temp, sizeof(temp), "table with name: \"%s%s%s\" doesn't contain primary key",
                has_schema_name? schema_name : "", has_schema_name? "\".\"" : "", table_name);

            throw std::runtime_error(temp);
        }
        else if(pk_columns.dim1 != 1)
        {
            char temp[256];
            bool has_schema_name = schema_name && *schema_name;
            snprintf(temp, sizeof(temp), "primary key for table with name: \"%s%s%s\" contain %d columns instead of 1",
                     has_schema_name? schema_name : "", has_schema_name? "\".\"" : "", table_name, pk_columns.dim1);

            throw std::runtime_error(temp);
        }

        SGTableLinked *new_table_linked;
        SGFullTableNameStorage* storage_table_name;
        if(!this->empty())
        {
            new_table_linked = this->alloc_item();
            storage_table_name = &table_names[new_table_linked->index];
        }
        else
        {
            // освобождаем элемент, которым дольше всего не пользовались
            new_table_linked = this->get_tail();
            storage_table_name = &table_names[new_table_linked->index];
            names_it = name2tables.find(SGFullTableName(storage_table_name->table_name, storage_table_name->schema_name));
            name2tables.erase(names_it);

            oids_it = oid2tables.find(new_table_linked->item().get_table_oid());
            oid2tables.erase(oids_it);

            new_table_linked->free();
            this->set_head(new_table_linked);
        }

        Oid namespace_oid = InvalidOid;
        Relation relation = try_relation_open(table_oid, AccessShareLock);
        if(relation)
        {
            namespace_oid = relation->rd_rel->relnamespace;
            relation_close(relation, AccessShareLock);
        }
        else
        {
            char temp[256];
            bool has_schema_name = schema_name && *schema_name;
            snprintf(temp, sizeof(temp), "table_oid[%d] for table with name: \"%s%s%s\" unexpectedly disappeared from database",
                     table_oid, has_schema_name? schema_name : "", has_schema_name? "\".\"" : "", table_name);

            throw std::runtime_error(temp);
        }

        SGTable& new_table = new_table_linked->create(m_context, table_oid, index_oid);
        if(schema_name && *schema_name)
            storage_table_name->setup(table_name, schema_name);
        else
        {
            bool is_null;
            Datum datum;
            HeapTuple tup = SearchSysCache1(NAMESPACEOID, ObjectIdGetDatum(namespace_oid));
            if(tup && (datum = SysCacheGetAttr(NAMESPACEOID, tup, Anum_pg_namespace_nspname, &is_null)), !is_null)
            {
                storage_table_name->setup(table_name, DatumGetCString(datum));
                ReleaseSysCache(tup);
            }
            else
                storage_table_name->setup(table_name, nullptr);
        }

        name2tables.emplace(SGFullTableName(storage_table_name->table_name, storage_table_name->schema_name), std::move(new_table_linked));
        oid2tables.emplace(std::move(table_oid), std::move(new_table_linked));

        return new_table;
    }
}

template<size_t tables_cache_size, size_t functions_cache_size>
SGTable& SGTableManager<tables_cache_size, functions_cache_size>::SGTableManagerCache::find(Oid table_oid)
{
    auto oids_it = oid2tables.find(table_oid);
    if(oids_it != oid2tables.end())
    {
        // нашли в кэше по oid - возвращаем кэшированное
        SGTableLinked* finded = oids_it->second;
        this->set_head(finded);

        return finded->item();
    }
    else
    {
        SGMemoryContextSwitcher mc(m_context);
        char table_name[NAMEDATALEN];
        Oid namespace_oid = InvalidOid;
        Relation relation = try_relation_open(table_oid, AccessShareLock);
        if(relation)
        {
            if (relation->rd_rel->relkind != RELKIND_RELATION)
            {
                char temp[256];
                snprintf(temp, sizeof(temp), "relation \"%s\" with oid: \"%d\" has type '%c' which is not table",
                    RelationGetRelationName(relation), table_oid, relation->rd_rel->relkind);
                relation_close(relation, AccessShareLock);

                throw std::runtime_error(temp);
            }

            ::memcpy(table_name, relation->rd_rel->relname.data, NAMEDATALEN);
            namespace_oid = relation->rd_rel->relnamespace;
            relation_close(relation, AccessShareLock);
        }
        else
        {
            char temp[256];
            snprintf(temp, sizeof(temp), "table with oid: \"%d\" doesn't exists in database", table_oid);

            throw std::runtime_error(temp);
        }

        int2vector pk_columns;
        Oid index_oid = find_table_pk_oid(table_oid, pk_columns);
        if(!OidIsValid(index_oid))
        {
            char temp[256];
            snprintf(temp, sizeof(temp), "table with oid: \"%d\" doesn't contain primary key", table_oid);

            throw std::runtime_error(temp);
        }
        else if(pk_columns.dim1 != 1)
        {
            char temp[256];
            snprintf(temp, sizeof(temp), "primary key for table with oid: \"%d\" contain %d columns instead of 1",
                     table_oid, pk_columns.dim1);

            throw std::runtime_error(temp);
        }

        SGTableLinked *new_table_linked;
        SGFullTableNameStorage* storage_table_name;
        if(!this->empty())
        {
            new_table_linked = this->alloc_item();
            storage_table_name = &table_names[new_table_linked->index];
        }
        else
        {
            // освобождаем элемент, которым дольше всего не пользовались
            new_table_linked = this->get_tail();
            storage_table_name = &table_names[new_table_linked->index];
            auto names_it = name2tables.find(SGFullTableName(storage_table_name->table_name, storage_table_name->schema_name));
            name2tables.erase(names_it);

            oids_it = oid2tables.find(new_table_linked->item().get_table_oid());
            oid2tables.erase(oids_it);

            new_table_linked->free();
            this->set_head(new_table_linked);
        }

        SGTable& new_table = new_table_linked->create(m_context, table_oid, index_oid);
        {
            bool is_null;
            Datum datum;
            HeapTuple tup = SearchSysCache1(NAMESPACEOID, ObjectIdGetDatum(namespace_oid));
            if(tup && (datum = SysCacheGetAttr(NAMESPACEOID, tup, Anum_pg_namespace_nspname, &is_null)), !is_null)
            {
                storage_table_name->setup(table_name, DatumGetCString(datum));
                ReleaseSysCache(tup);
            }
            else
                storage_table_name->setup(table_name, nullptr);
        }

        name2tables.emplace(SGFullTableName(storage_table_name->table_name, storage_table_name->schema_name), std::move(new_table_linked));
        oid2tables.emplace(std::move(table_oid), std::move(new_table_linked));

        return new_table;
    }
}

template<size_t tables_cache_size, size_t functions_cache_size>
void SGTableManager<tables_cache_size, functions_cache_size>::SGTableManagerCache::clean()
{
    for(auto[key, value] : oid2tables)
    {
        (void) key;
        value->free();
        this->free_item(value);
    }

    name2tables.clear();
    oid2tables.clear();
}

template<size_t tables_cache_size, size_t functions_cache_size>
bool SGTableManager<tables_cache_size, functions_cache_size>::SGTableManagerCache::pop(const char* table_name, const char* schema_name)
{
    auto names_it = name2tables.find(SGFullTableName(table_name, schema_name));
    if(names_it != name2tables.end())
    {
        // нашли в кэше по имени - выталкиваем из кэша
        SGTableLinked* holder = names_it->second;

        auto oid_it = oid2tables.find(holder->item().get_table_oid());
        holder->free();
        this->free_item(holder);

        name2tables.erase(names_it);
        oid2tables.erase(oid_it);

        return true;
    }
    else
    {
        SGMemoryContextSwitcher mc(m_context);
        Oid table_oid = find_table_oid(table_name, schema_name);
        return OidIsValid(table_oid)? pop(table_oid) : false;
    }
}

template<size_t tables_cache_size, size_t functions_cache_size>
bool SGTableManager<tables_cache_size, functions_cache_size>::SGTableManagerCache::pop(Oid table_oid)
{
    auto oid_it = oid2tables.find(table_oid);
    if(oid_it != oid2tables.end())
    {
        // нашли в кэше по oid - выталкиваем из кэша
        SGTableLinked* holder = oid_it->second;

        SGFullTableNameStorage* storage_table_name = &table_names[holder->index];
        auto names_it = name2tables.find(SGFullTableName(storage_table_name->table_name, storage_table_name->schema_name));
        holder->free();
        this->free_item(holder);

        name2tables.erase(names_it);
        oid2tables.erase(oid_it);

        return true;
    }

    return false;
}

template<size_t tables_cache_size, size_t functions_cache_size>
Oid SGTableManager<tables_cache_size, functions_cache_size>::SGTableManagerCache::find_table_oid(const char* table_name, const char* schema_name)
{
    if(!table_name || !*table_name)
        return InvalidOid;

    SGTransaction transaction; (void) transaction;
    if(schema_name && *schema_name)
    {
        Oid schema_id = LookupExplicitNamespace(schema_name, true);
        return OidIsValid(schema_id)? get_relname_relid(table_name, schema_id) : InvalidOid;
    }
    else
        return RelnameGetRelid(table_name);
}

template<size_t tables_cache_size, size_t functions_cache_size>
Oid SGTableManager<tables_cache_size, functions_cache_size>::SGTableManagerCache::find_table_pk_oid(Oid table_oid, int2vector& pk_columns)
{
    ScanKeyData skey;
    HeapTuple htup;
    Oid pkey_oid = InvalidOid;
    ScanKeyInit(&skey, Anum_pg_index_indrelid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(table_oid));
    Relation indrel = table_open(IndexRelationId, AccessShareLock);
    SysScanDesc indscan = systable_beginscan(indrel, IndexIndrelidIndexId, true, NULL, 1, &skey);
    while (HeapTupleIsValid(htup = systable_getnext(indscan)))
    {
        Form_pg_index index = (Form_pg_index) GETSTRUCT(htup);

        /*
         * Ignore any indexes that are currently being dropped.  This will
         * prevent them from being searched, inserted into, or considered in
         * HOT-safety decisions.  It's unsafe to touch such an index at all
         * since its catalog entries could disappear at any instant.
         */
        if (!index->indislive)
            continue;

        /*
         * Invalid, non-unique, non-immediate or predicate indexes aren't
         * interesting for either oid indexes or replication identity indexes,
         * so don't check them.
         */
        if (!index->indisvalid || !index->indisunique ||
            !index->indimmediate ||
            !heap_attisnull(htup, Anum_pg_index_indpred, NULL))
            continue;

        /* remember primary key index if any */
        if (index->indisprimary)
        {
            pkey_oid = index->indexrelid;
            pk_columns = index->indkey;
        }
    }

    systable_endscan(indscan);
    table_close(indrel, AccessShareLock);
    return pkey_oid;
}

SGMemoryContext::SGMemoryContext() : m_context(create_own_memory_context(nullptr))
{
}

SGMemoryContext::SGMemoryContext(MemoryContext parent) : m_context(create_own_memory_context(parent))
{
}

SGMemoryContext::~SGMemoryContext()
{
    MemoryContextDelete(m_context);
}

MemoryContext SGMemoryContext::create_own_memory_context(MemoryContext parent)
{
    SGMemoryContextSwitcher mc(parent);
    return AllocSetContextCreate(CurrentMemoryContext, "SGTableManager", ALLOCSET_DEFAULT_SIZES);
}

SGTransaction::SGTransaction()
{
    is_already_started = IsTransactionState();
    if(!is_already_started)
        StartTransactionCommand();
}

SGTransaction::~SGTransaction()
{
    if(!is_already_started)
        AbortCurrentTransaction();
}

DataTypeDesc::DataTypeDesc(Oid type_oid)
{
    if((is_type_defined = get_typisdefined(type_oid)))
    {
        Oid typoutput;
        bool typisvarlena;
        getTypeOutputInfo(type_oid, &typoutput, &typisvarlena);
        fmgr_info(typoutput, &text_out_func);

        getTypeBinaryOutputInfo(type_oid, &typoutput, &typisvarlena);
        fmgr_info(typoutput, &binary_out_func);

        base_attt_mod = -1;
        base_atttype_id = getBaseTypeAndTypmod(type_oid, &base_attt_mod);
    }
}

void DataTypeDesc::write_string_to_pipe(const std::function<void(const void*, size_t)>& func, const char *buffer)
{
    size_t size = buffer? strlen(buffer) : 0;
    uint32 ni = pg_hton32(size);
    func(&ni, 4);
    if(size) func(buffer, size);
}

template<size_t tables_cache_size, size_t functions_cache_size>
SGTableManager<tables_cache_size, functions_cache_size>::SGTableManager() : context(), cache(context.context()),
    type_out_funcs{}
{
}

template<size_t tables_cache_size, size_t functions_cache_size>
SGTableManager<tables_cache_size, functions_cache_size>::SGTableManager(MemoryContext m_context) : context(m_context), cache(m_context),
    type_out_funcs{}
{
}

template<size_t tables_cache_size, size_t functions_cache_size>
SGTableManager<tables_cache_size, functions_cache_size>::~SGTableManager()
{
}

template<size_t tables_cache_size, size_t functions_cache_size>
bool SGTableManager<tables_cache_size, functions_cache_size>::print(const char* table_name, const char* schema_name, int key_value, bool use_binary_format)
{
    SGTransaction transaction; (void) transaction;
    SGTable& sg_table = cache.find(table_name, schema_name);
    std::function<void(bool, TupleTableSlot*)> output_func = [this](bool binary_format, TupleTableSlot *slot){
        this->print_slot(binary_format, slot);
    };

    return sg_table.fetch(key_value, use_binary_format, &output_func, true);
}

template<size_t tables_cache_size, size_t functions_cache_size>
bool SGTableManager<tables_cache_size, functions_cache_size>::print(Oid table_oid, int key_value, bool use_binary_format)
{
    SGTransaction transaction; (void) transaction;
    SGTable& sg_table = cache.find(table_oid);
    std::function<void(bool, TupleTableSlot*)> output_func = [this](bool binary_format, TupleTableSlot *slot){
        this->print_slot(binary_format, slot);
    };

    return sg_table.fetch(key_value, use_binary_format, &output_func, true);
}

template<size_t tables_cache_size, size_t functions_cache_size>
bool SGTableManager<tables_cache_size, functions_cache_size>::fetch(const char* table_name, const char* schema_name,
    int32_t key_value, bool use_binary_format, const std::function<void(const void*, size_t)>& func)
{
    std::function<void(bool, TupleTableSlot*)> output_func = [this, &func](bool binary_format, TupleTableSlot *slot){
        this->fetch_slot(binary_format, slot, func);
    };

    SGTransaction transaction; (void) transaction;
    SGTable& sg_table = cache.find(table_name, schema_name);
    return sg_table.fetch(key_value, use_binary_format, &output_func, false);
}

template<size_t tables_cache_size, size_t functions_cache_size>
bool SGTableManager<tables_cache_size, functions_cache_size>::fetch(Oid table_oid, int32_t key_value,
    bool use_binary_format, const std::function<void(const void*, size_t)>& func)
{
    std::function<void(bool, TupleTableSlot*)> output_func = [this, &func](bool binary_format, TupleTableSlot *slot){
        this->fetch_slot(binary_format, slot, func);
    };

    SGTransaction transaction; (void) transaction;
    SGTable& sg_table = cache.find(table_oid);
    return sg_table.fetch(key_value, use_binary_format, &output_func, false);
}

template<size_t tables_cache_size, size_t functions_cache_size>
bool SGTableManager<tables_cache_size, functions_cache_size>::meta(const char* table_name, const char* schema_name,
    const std::function<void(const void*, size_t)>& func)
{
    SGTransaction transaction; (void) transaction;
    Oid table_oid = SGTableManager<tables_cache_size, functions_cache_size>::SGTableManagerCache::find_table_oid(table_name, schema_name);
    return OidIsValid(table_oid)? meta(table_oid, func) : false;
}

template<size_t tables_cache_size, size_t functions_cache_size>
bool SGTableManager<tables_cache_size, functions_cache_size>::meta(Oid table_oid, const std::function<void(const void*, size_t)>& func)
{
    SGTransaction transaction; (void) transaction;
    SGMemoryContextSwitcher mc(context.context());
    Relation relation = try_relation_open(table_oid, AccessShareLock);
    if(relation)
    {
        bool result = relation->rd_rel->relkind == RELKIND_RELATION;
        if (result)
        {
            DataTypeDesc::write_int32_to_pipe(func, table_oid);

            TupleDesc attrs = relation->rd_att;
            int natts = 0;
            for (int i = 0 ; i < attrs->natts ; i++)
                if(!attrs->attrs[i].attisdropped)
                    natts++;

            DataTypeDesc::write_int16_to_pipe(func, natts);
            for (int i = 0 ; i < attrs->natts ; i++)
            {
                FormData_pg_attribute *attr = &attrs->attrs[i];
                if(!attr->attisdropped)
                {
                    DataTypeDesc::write_string_to_pipe(func, attr->attname.data);
                    DataTypeDesc::write_int32_to_pipe(func, attr->attrelid);
                    DataTypeDesc::write_int16_to_pipe(func, attr->attnum);
                    DataTypeDesc::write_int32_to_pipe(func, attr->atttypid);
                    DataTypeDesc::write_int16_to_pipe(func, attr->attlen);
                    DataTypeDesc::write_int32_to_pipe(func, attr->attstattarget);
                    DataTypeDesc::write_int16_to_pipe(func, 1); // use binary_format
                }
            }
        }

        relation_close(relation, AccessShareLock);
        return result;
    }

    return false;
}

template<size_t tables_cache_size, size_t functions_cache_size>
void SGTableManager<tables_cache_size, functions_cache_size>::clean()
{
    cache.clean();
}

template<size_t tables_cache_size, size_t functions_cache_size>
bool SGTableManager<tables_cache_size, functions_cache_size>::pop(const char* table_name, const char* schema_name)
{
    return cache.pop(table_name, schema_name);
}

template<size_t tables_cache_size, size_t functions_cache_size>
bool SGTableManager<tables_cache_size, functions_cache_size>::pop(Oid table_oid)
{
    return cache.pop(table_oid);
}

template<size_t tables_cache_size, size_t functions_cache_size>
void SGTableManager<tables_cache_size, functions_cache_size>::print_slot(bool binary_format, TupleTableSlot *slot)
{
    TupleDesc tuple_descriptor = slot->tts_tupleDescriptor;
    int natts = tuple_descriptor->natts;
    bool* tts_isnull = slot->tts_isnull;
    Datum* tts_values = slot->tts_values;

    for (int i = 0; i < natts; i++)
    {
        FormData_pg_attribute *attr = &tuple_descriptor->attrs[i];

        if(!attr->attisdropped)
        {
            DataTypeDesc& pair_out_func = type_out_funcs.get_or_create(attr->atttypid, &get_out_func);
            if(!pair_out_func.IsTypeDefined())
            {
                char temp[256];
                snprintf(temp, sizeof(temp), "Attribute \"%s\" has invalid type id: %d, but not dropped", attr->attname.data, attr->atttypid);

                throw std::runtime_error(temp);
            }

            if (tts_isnull[i])
                std::cout << attr->attname.data << "-> is null" << std::endl;
            else
            {
                if (binary_format)
                {
                    /* Binary output */
                    bytea *outputbytes = pair_out_func.SendFunctionCall(tts_values[i], slot->tts_mcxt);
                    std::cout << attr->attname.data << " -> len[" << VARSIZE(outputbytes) - VARHDRSZ <<
                              "/" << VARSIZE(outputbytes) - VARHDRSZ << ']' << std::endl;
                }
                else
                {
                    /* Text output */
                    char *outputstr = pair_out_func.OutputFunctionCall(tts_values[i], slot->tts_mcxt);
                    std::cout << attr->attname.data << "-> " << outputstr << std::endl;
                }
            }
        }
    }
}

template<size_t tables_cache_size, size_t functions_cache_size>
void SGTableManager<tables_cache_size, functions_cache_size>::fetch_slot(
    bool binary_format, TupleTableSlot *slot, const std::function<void(const void*, size_t)>& func)
{
    TupleDesc tuple_descriptor = slot->tts_tupleDescriptor;
    int natts = tuple_descriptor->natts;
    bool* tts_isnull = slot->tts_isnull;
    Datum* tts_values = slot->tts_values;
    static const size_t null_value = -1;

    int __natts = 0;
    for (int i = 0 ; i < natts ; i++)
        if(!tuple_descriptor->attrs[i].attisdropped)
            __natts++;

    DataTypeDesc::write_int16_to_pipe(func, __natts);

    for (int i = 0; i < natts; i++)
    {
        FormData_pg_attribute *attr = &tuple_descriptor->attrs[i];

        if(!attr->attisdropped)
        {
            DataTypeDesc& pair_out_func = type_out_funcs.get_or_create(attr->atttypid, &get_out_func);
            if(!pair_out_func.IsTypeDefined())
            {
                char temp[256];
                snprintf(temp, sizeof(temp), "Attribute \"%s\" has invalid type id: %d, but not dropped", attr->attname.data, attr->atttypid);

                throw std::runtime_error(temp);
            }

            if (tts_isnull[i])
                DataTypeDesc::write_buffer_to_pipe(func, &null_value, 4);
            else
            {
                if(binary_format)
                {
                    /* Binary output */
                    bytea* outputbytes = pair_out_func.SendFunctionCall(tts_values[i], slot->tts_mcxt);
                    DataTypeDesc::write_int32_to_pipe(func, VARSIZE(outputbytes) - VARHDRSZ);
                    DataTypeDesc::write_buffer_to_pipe(func, VARDATA(outputbytes), VARSIZE(outputbytes) - VARHDRSZ);
                }
                else
                {
                    /* Text output */
                    char *outputstr = pair_out_func.OutputFunctionCall(tts_values[i], slot->tts_mcxt);
                    DataTypeDesc::write_string_to_pipe(func, outputstr);
                }
            }
        }
    }
}

}

constexpr size_t TABLE_CACHE_SIZE = 64;
constexpr size_t OUTPUT_FUNCTION_CACHE_SIZE = 64;

static sgaz::SGTableManager<TABLE_CACHE_SIZE, OUTPUT_FUNCTION_CACHE_SIZE>& table_manager()
{
    static std::unique_ptr<sgaz::SGTableManager<TABLE_CACHE_SIZE, OUTPUT_FUNCTION_CACHE_SIZE>> cache(
        new sgaz::SGTableManager<TABLE_CACHE_SIZE, OUTPUT_FUNCTION_CACHE_SIZE>(TopMemoryContext)
    );
    return *cache;
}

std::function<void(const void*, size_t)> pipe_vector(std::vector<char>& storage)
{
    return [&storage](const void* buffer, size_t size)
    {
        storage.insert(storage.end(), reinterpret_cast<const char*>(buffer), reinterpret_cast<const char*>(buffer) + size);
        return true;
    };
};

void printByKeyTableName(const std::string& table_name, const std::string& schema_name, int32_t key_value, bool use_binary_format = false)
{
    table_manager().print(table_name.c_str(), schema_name.c_str(), key_value, use_binary_format);
}

void printByKeyTableOid(int32_t table_oid, int32_t key_value, bool use_binary_format = false)
{
    table_manager().print(table_oid, key_value, use_binary_format);
}

void fetchByKeyTableName(const char* table_name, const char* schema_name, int32_t key_value,
                         bool use_binary_format, const std::function<void(const void*, size_t)>& func)
{
    table_manager().fetch(table_name, schema_name, key_value, use_binary_format, func);
}

void fetchByKeyTableOid(int32_t table_oid, int32_t key_value, bool use_binary_format,
    const std::function<void(const void*, size_t)>& func)
{
    table_manager().fetch(table_oid, key_value, use_binary_format, func);
}

bool metaByTableOid(int32_t table_oid, const std::function<void(const void*, size_t)>& func)
{
    return table_manager().meta(table_oid, func);
}

bool metaByTableName(const char* table_name, const char * schema_name,
                     const std::function<void(const void*, size_t)>& func)
{
    return table_manager().meta(table_name, schema_name, func);
}
