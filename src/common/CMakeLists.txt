if(OPENSSL_FOUND)
	include_directories(BEFORE ${OPENSSL_INCLUDE_DIR})
endif()

file(GLOB pgcommon_srv_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/*.c)
file(GLOB exclude_pgcommon_srv_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/fe_*.c ${CMAKE_CURRENT_SOURCE_DIR}/restricted_token.c)
list(REMOVE_ITEM pgcommon_srv_SRCS ${exclude_pgcommon_srv_SRCS})
list(REMOVE_ITEM pgcommon_srv_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/sha2_openssl.c ${CMAKE_CURRENT_SOURCE_DIR}/sha2.c)

if(OPENSSL_FOUND AND NOT WIN32)
	set(pgcommon_srv_SRCS ${pgcommon_srv_SRCS} sha2_openssl.c)
else()
	set(pgcommon_srv_SRCS ${pgcommon_srv_SRCS} sha2.c)
endif()

set(pgcommon_SRCS
	${pgcommon_srv_SRCS}
	fe_memutils.c
	file_utils.c
	restricted_token.c
	${PROJECT_SOURCE_DIR}/src/include/parser/gram.h
)

add_library(pgcommon_srv STATIC ${pgcommon_srv_SRCS})
add_library(pgcommon STATIC ${pgcommon_SRCS})

set_source_files_properties(
	${PROJECT_SOURCE_DIR}/src/include/parser/gram.h
	PROPERTIES GENERATED TRUE
)

add_dependencies(pgcommon_srv generate_parser_gram_h)
add_dependencies(pgcommon_srv gen_errorcodes)
add_dependencies(pgcommon gen_errorcodes)

target_compile_definitions(pgcommon PRIVATE -DFRONTEND)

target_compile_definitions(pgcommon PRIVATE -DVAL_CPPFLAGS="${CMAKE_CXX_FLAGS}")
target_compile_definitions(pgcommon PRIVATE -DVAL_CFLAGS="${CMAKE_C_FLAGS} ${COMPILE_DEFINITIONS}")
target_compile_definitions(pgcommon PRIVATE -DVAL_CC="${CMAKE_C_COMPILER}")
target_compile_definitions(pgcommon PRIVATE -DVAL_LDFLAGS="${CMAKE_SHARED_LINKER_FLAGS}")

# because port used in shared libraries
set_property(TARGET pgcommon PROPERTY POSITION_INDEPENDENT_CODE TRUE)

install(TARGETS pgcommon
		ARCHIVE DESTINATION ${LIBDIR})
