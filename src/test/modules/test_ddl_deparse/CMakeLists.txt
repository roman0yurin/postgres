option(PGXS "Separate build" OFF)
if(PGXS)
	cmake_minimum_required(VERSION 3.5)
	find_package(PostgreSQL)
	include(${PostgreSQL_LIBRARY_DIRS}/cmake/PGXS.cmake)
else()
	include_directories("${PROJECT_SOURCE_DIR}/src/include")
endif()

set(extension_name test_ddl_deparse)

if(${CMAKE_HOST_SYSTEM_VERSION} MATCHES "^([^\\.]+\\.)+el7\\.x86_64$")
	get_property(LLVM_LIBRARY_DIRS GLOBAL PROPERTY LLVM_LIBRARY_DIRS)
	link_directories(${LLVM_LIBRARY_DIRS})
endif()

add_library(${extension_name} ${PLUGIN_TYPE}
	test_ddl_deparse.c
)
target_link_libraries(${extension_name} ${modules_libs})
set_target_properties(${extension_name} PROPERTIES PREFIX "")
if (MSVC)
	gen_def(${extension_name})
endif()
if(NOT PGXS)
	add_dependencies(${extension_name} postgres)
	CMAKE_SET_TARGET_FOLDER(${extension_name} modules)
endif()
install(TARGETS ${extension_name}
		RUNTIME DESTINATION ${PGBINDIR}
		LIBRARY DESTINATION ${LIBDIR})
install(FILES ${extension_name}.control ${extension_name}--1.0.sql
	DESTINATION ${PGSHAREDIR}/extension)

set(tests_list
	test_ddl_deparse
	create_extension
	create_schema
	create_type
	create_conversion
	create_domain
	create_sequence_1
	create_table
	create_transform
	alter_table
	create_view
	create_trigger
	create_rule
	comment_on
	alter_function
	alter_sequence
	alter_type_enum
	opfamily
	defprivs
	matviews
)

MODULES_REGRESS_CHECK(${extension_name} "--dbname=contrib_regression" "${tests_list}")
