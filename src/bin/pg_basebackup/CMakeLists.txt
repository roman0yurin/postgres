include_directories(BEFORE
	"${PROJECT_SOURCE_DIR}/src/include/libpq"
	"${PROJECT_SOURCE_DIR}/src/interfaces/libpq"
	"${PROJECT_SOURCE_DIR}/src/bin/pg_dump"
	${ZLIB_INCLUDE_DIRS}
)
if(ZLIB_FOUND)
	include_directories(BEFORE ${ZLIB_INCLUDE_DIRS})
endif()

set(common_basebackup_SRC
	receivelog.c
	streamutil.c
	walmethods.c
)

set(basebackup_list 
	pg_basebackup
	pg_receivewal
	pg_recvlogical
)

foreach(loop_var IN ITEMS ${basebackup_list})
	add_executable(${loop_var} ${loop_var}.c ${common_basebackup_SRC})

	target_link_libraries(${loop_var}
		pgfeutils
		pq
		pgcommon
		pgport
		${M_LIB}
	)
	CMAKE_SET_TARGET_FOLDER(${loop_var} bin)
	if(ZLIB_FOUND)
		target_link_libraries(${loop_var} ${ZLIB_LIBRARIES})
	endif()
endforeach()

install(TARGETS ${basebackup_list}
		RUNTIME DESTINATION ${PGBINDIR}
		LIBRARY DESTINATION ${LIBDIR})

if(ENABLE_NLS)
	MAKE_MO(pg_basebackup "de;es;fr;it;ko;pl;pt_BR;ru;zh_CN;he")
endif()

if(PROVE)
	TAP_CHECK("pg_basebackup_tap" "${TAP_FLAGS}" "t/*.pl")
endif()
