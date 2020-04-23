include_directories(
	"${PROJECT_SOURCE_DIR}/src/include"
	"${PROJECT_SOURCE_DIR}/src/interfaces/libpq"
)

set(extension_name oid2name)

if(${CMAKE_HOST_SYSTEM_VERSION} MATCHES "^([^\\.]+\\.)+el7\\.x86_64$")
	get_property(LLVM_LIBRARY_DIRS GLOBAL PROPERTY LLVM_LIBRARY_DIRS)
	link_directories(${LLVM_LIBRARY_DIRS})
endif()

add_library(${extension_name} ${PLUGIN_TYPE} ${extension_name}.c)
target_link_libraries(${extension_name} ${contrib_libs})
if(MSVC)
	gen_def(${extension_name})
endif()

if(MSVC OR MINGW)
	target_link_libraries(${extension_name} pgcommon pq)
endif()

if(NOT PGXS)
	CMAKE_SET_TARGET_FOLDER(${extension_name} contrib)
endif()
set_target_properties(${extension_name} PROPERTIES PREFIX "")
add_dependencies(${extension_name} postgres)
install(TARGETS ${extension_name}
		RUNTIME DESTINATION ${PGBINDIR}
		LIBRARY DESTINATION ${LIBDIR})
