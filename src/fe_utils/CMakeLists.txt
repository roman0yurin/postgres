include_directories(BEFORE
	"${PROJECT_SOURCE_DIR}/src/include/libpq"
	"${PROJECT_SOURCE_DIR}/src/interfaces/libpq"
	"${PROJECT_SOURCE_DIR}/src/bin/pg_dump"
	"${PROJECT_SOURCE_DIR}/src/bin/psql"
)

set(psqlscan_flags, "-Cfe -p -p")

flex_target(psqlscan
	psqlscan.l
	${CMAKE_CURRENT_SOURCE_DIR}/psqlscan.c
	${psqlscan_flags}
)

file(GLOB_RECURSE pgfeutils_SRC ${CMAKE_CURRENT_SOURCE_DIR}/*.c)

add_library(pgfeutils STATIC
	${pgfeutils_SRC}
	${FLEX_psqlscan_OUTPUTS}
)
