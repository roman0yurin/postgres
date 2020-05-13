include_directories(BEFORE
	"${CMAKE_CURRENT_SOURCE_DIR}"
	"${PROJECT_SOURCE_DIR}/src/port"
	"${PROJECT_SOURCE_DIR}/src/interfaces/ecpg/include"
	"${PROJECT_SOURCE_DIR}/src/interfaces/libpq"
)
set(ecpg_SRC
	execute.c
	typename.c
	descriptor.c
	sqlda.c
	data.c
	error.c
	prepare.c
	memory.c
	connect.c
	misc.c
	${PROJECT_SOURCE_DIR}/src/port/path.c
	${PROJECT_SOURCE_DIR}/src/port/pgstrcasecmp.c
)

if(USE_REPL_SNPRINTF)
	set(ecpg_SRC
		${ecpg_SRC}
		${PROJECT_SOURCE_DIR}/src/port/snprintf.c
	)
endif()

if(NOT HAVE_RINT)
	set(ecpg_SRC
		${ecpg_SRC}
		${PROJECT_SOURCE_DIR}/src/port/rint.c
	)
endif()

if(NOT HAVE_DECL_STRLCPY)
	set(ecpg_SRC
		${ecpg_SRC}
		${PROJECT_SOURCE_DIR}/src/port/strlcpy.c
	)
endif()

if(NOT HAVE_ISINF)
	set(ecpg_SRC
		${ecpg_SRC}
		${PROJECT_SOURCE_DIR}/src/port/isinf.c
	)
endif()

if(WIN32)
	set(ecpg_SRC
		${ecpg_SRC}
		${PROJECT_SOURCE_DIR}/src/port/win32setlocale.c
	)
else()
	set(ecpg_SRC
		${ecpg_SRC}
		${PROJECT_SOURCE_DIR}/src/port/thread.c
	)
endif()

add_library(ecpg SHARED ${ecpg_SRC})
if (MSVC)
	gen_def(ecpg)
endif()

target_link_libraries(ecpg
	PRIVATE pgtypes
	PRIVATE pgcommon_shlib
	PRIVATE pgport_shlib
	PRIVATE pq
	PRIVATE	${LIB_M}
)

add_custom_command(TARGET ecpg
	PRE_LINK
	COMMAND echo '{ global:' > exports.list
	COMMAND gawk '/^[^\#]/ {printf \"%s\;\\n\",$$1}' ${CMAKE_CURRENT_SOURCE_DIR}/exports.txt >> exports.list
	COMMAND echo ' local: *\; }\;' >> exports.list
)

target_compile_definitions(ecpg PRIVATE -DFRONTEND)
set_target_properties(ecpg PROPERTIES VERSION "6.12" SOVERSION "6")
set (CMAKE_SHARED_LINKER_FLAGS ${CMAKE_SHARED_LINKER_FLAGS} "-Wl,--version-script=exports.list")

install(TARGETS ecpg
		RUNTIME DESTINATION ${PGBINDIR}
		LIBRARY DESTINATION ${LIBDIR})

if(ENABLE_NLS)
	MAKE_MO(ecpg "cs;de;es;fr;it;ja;ko;pl;pt_BR;ru;tr;zh_CN")
endif()
