include_directories(BEFORE
	"${CMAKE_CURRENT_SOURCE_DIR}"
	"${PROJECT_SOURCE_DIR}/src/port"
	"${PROJECT_SOURCE_DIR}/src/interfaces/ecpg/include"
	"${PROJECT_SOURCE_DIR}/src/interfaces/libpq"
)
set(ecpg_compat_SRC
	informix.c
)
if(USE_REPL_SNPRINTF)
	set(ecpg_compat_SRC
		${ecpg_compat_SRC}
		${PROJECT_SOURCE_DIR}/src/port/snprintf.c
	)
endif()

add_library(ecpg_compat SHARED ${ecpg_compat_SRC})
if (MSVC)
	gen_def(ecpg_compat)
endif()

target_link_libraries(ecpg_compat
	PRIVATE ecpg
	PRIVATE pgtypes
	PRIVATE pgcommon_shlib
	PRIVATE pgport_shlib
	PRIVATE pq
	PRIVATE ${LIB_M}
)

add_custom_command(TARGET ecpg_compat
	PRE_LINK
	COMMAND echo '{ global:' > exports.list
	COMMAND gawk '/^[^\#]/ {printf \"%s\;\\n\",$$1}' ${CMAKE_CURRENT_SOURCE_DIR}/exports.txt >> exports.list
	COMMAND echo ' local: *\; }\;' >> exports.list
)

target_compile_definitions(ecpg_compat PRIVATE -DFRONTEND)
set_target_properties(ecpg_compat PROPERTIES VERSION "3.12" SOVERSION "3")
set (CMAKE_SHARED_LINKER_FLAGS ${CMAKE_SHARED_LINKER_FLAGS} "-Wl,--version-script=exports.list")

install(TARGETS ecpg_compat
		RUNTIME DESTINATION ${PGBINDIR}
		LIBRARY DESTINATION ${LIBDIR})
