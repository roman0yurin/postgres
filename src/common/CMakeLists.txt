if(OPENSSL_FOUND)
	include_directories(BEFORE ${OPENSSL_INCLUDE_DIR})
endif()

set(gen_lwlocknames_depend
		${PROJECT_SOURCE_DIR}/src/backend/storage/lmgr/generate-lwlocknames.pl
		${PROJECT_SOURCE_DIR}/src/backend/storage/lmgr/lwlocknames.txt
)

set(gen_lwlocknames_output
		${PROJECT_SOURCE_DIR}/src/backend/storage/lmgr/lwlocknames.c
		${PROJECT_SOURCE_DIR}/src/backend/storage/lmgr/lwlocknames.h
		${PROJECT_SOURCE_DIR}/src/include/storage/lwlocknames.h
)

add_custom_command(
		OUTPUT ${gen_lwlocknames_output}
		MAIN_DEPENDENCY ${gen_lwlocknames_depend}
		COMMAND ${PERL_EXECUTABLE} generate-lwlocknames.pl lwlocknames.txt
		COMMAND ${CMAKE_COMMAND} -E copy lwlocknames.h ${PROJECT_SOURCE_DIR}/src/include/storage/lwlocknames.h
		WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src/backend/storage/lmgr
)

add_custom_target(gen_lwlocknames_target DEPENDS ${gen_lwlocknames_output})

set(pgcommon_SRCS
	base64.c
	config_info.c
	controldata_utils.c
	d2s.c
	exec.c
	f2s.c
	file_perm.c
	ip.c
	keywords.c
	kwlookup.c
	link-canary.c
	md5.c
	pg_lzcompress.c
	pgfnames.c
	psprintf.c
	relpath.c
	rmtree.c
	saslprep.c
	scram-common.c
	string.c
	unicode_norm.c
	username.c
	wait_error.c
)
list(APPEND pgcommon_srv_SRCS ${gen_lwlocknames_output})
if(OPENSSL_FOUND AND NOT WIN32)
	list(APPEND pgcommon_srv_SRCS sha2_openssl.c)
else()
	list(APPEND pgcommon_srv_SRCS sha2.c)
endif()

set(pgfrontend_SRCS
	${pgcommon_SRCS}
	fe_memutils.c
	file_utils.c
	logging.c
	restricted_token.c
	${PROJECT_SOURCE_DIR}/src/include/parser/gram.h
)

add_library(pgcommon STATIC ${pgfrontend_SRCS})
add_library(pgcommon_shlib STATIC ${pgfrontend_SRCS})
add_library(pgcommon_srv STATIC ${pgcommon_SRCS})

set_source_files_properties(
	${PROJECT_SOURCE_DIR}/src/include/parser/gram.h
	PROPERTIES GENERATED TRUE
)

add_dependencies(pgcommon_srv generate_parser_gram_h gen_lwlocknames_target)
add_dependencies(pgcommon_srv gen_errorcodes)
add_dependencies(pgcommon gen_errorcodes)

target_compile_definitions(pgcommon PRIVATE -DFRONTEND)
target_compile_definitions(pgcommon_shlib PRIVATE -DFRONTEND)

# because port used in shared libraries
set_property(TARGET pgcommon_shlib PROPERTY POSITION_INDEPENDENT_CODE TRUE)

install(TARGETS pgcommon
		ARCHIVE DESTINATION ${LIBDIR})
