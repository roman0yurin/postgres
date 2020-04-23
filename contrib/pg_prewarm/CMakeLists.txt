include_directories("${PROJECT_SOURCE_DIR}/src/include")

set(extension_name pg_prewarm)

if(${CMAKE_HOST_SYSTEM_VERSION} MATCHES "^([^\\.]+\\.)+el7\\.x86_64$")
	get_property(LLVM_LIBRARY_DIRS GLOBAL PROPERTY LLVM_LIBRARY_DIRS)
	link_directories(${LLVM_LIBRARY_DIRS})
endif()

add_library(${extension_name} ${PLUGIN_TYPE} ${extension_name}.c)
target_link_libraries(${extension_name} ${contrib_libs})
set_target_properties(${extension_name} PROPERTIES PREFIX "")
add_dependencies(${extension_name} postgres)
if(MSVC)
	gen_def(${extension_name})
endif()
if(NOT PGXS)
	CMAKE_SET_TARGET_FOLDER(${extension_name} contrib)
endif()
install(TARGETS ${extension_name}
		RUNTIME DESTINATION ${PGBINDIR}
		LIBRARY DESTINATION ${LIBDIR})
install(FILES
	${extension_name}.control
	${extension_name}--1.1.sql
	${extension_name}--1.0--1.1.sql
	DESTINATION ${PGSHAREDIR}/extension)
