#Библиотека - адаптер JIT компилятора для postgres
cmake_minimum_required(VERSION 3.5)
project(llvmjit C CXX)

if(${CMAKE_HOST_SYSTEM_VERSION} MATCHES "^([^\\.]+\\.)+el7\\.x86_64$")
	find_package(LLVM 5.0 REQUIRED)
else()
	find_package(LLVM REQUIRED CONFIG)
endif()

add_definitions(${LLVM_DEFINITIONS})
include_directories(BEFORE ${LLVM_INCLUDE_DIRS})

#Переключаемся на CLANG в этом пакете
if(${CMAKE_HOST_SYSTEM_VERSION} MATCHES "^([^\\.]+\\.)+el7\\.x86_64$")
	SET (CMAKE_C_COMPILER             "/opt/rh/llvm-toolset-7/root/usr/bin/clang")
	SET (CMAKE_CXX_COMPILER           "/opt/rh/llvm-toolset-7/root/usr/bin/clang++")
else()
	SET (CMAKE_C_COMPILER             "/usr/bin/clang")
	SET (CMAKE_CXX_COMPILER           "/usr/bin/clang++")
endif()

SET (CMAKE_AR                     "/usr/bin/llvm-ar")
SET (CMAKE_LINKER                 "/usr/bin/llvm-ld")
SET (CMAKE_NM                     "/usr/bin/llvm-nm")
SET (CMAKE_OBJDUMP                "/usr/bin/llvm-objdump")
SET (CMAKE_RANLIB                 "/usr/bin/llvm-ranlib")

SET (CMAKE_C_FLAGS                "${CMAKE_C_FLAGS} -Wno-ignored-attributes -std=c99")

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} ${LLVM_CXXFLAGS} -Wall -Wextra -Wno-unused-parameter -Wno-ignored-attributes -Wno-c99-extensions")
set(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} ${LLVM_CFLAGS} -Wall -Wextra -Wno-unused-parameter -Wno-ignored-attributes -Wno-c99-extensions -std=c99")

get_property(POSTGRES_SRC_DIR GLOBAL PROPERTY POSTGRES_SRC_DIR)
get_property(POSTGRES_LIB_DIR GLOBAL PROPERTY POSTGRES_LIB_DIR)
get_property(POSTGRES_BIN_DIR GLOBAL PROPERTY POSTGRES_BIN_DIR)
get_property(db_extensions_sql GLOBAL PROPERTY db_extensions_sql)


#Добавляем зависимость от Postgres
get_property(POSTGRES_INCLUDE_DIRS GLOBAL PROPERTY POSTGRES_INCLUDE_DIRS)
get_property(POSTGRES_INCLUDE_ROOT GLOBAL PROPERTY POSTGRES_INCLUDE_ROOT)
get_property(POSTGRES_DISTRIB_LIB_DIR GLOBAL PROPERTY POSTGRES_DISTRIB_LIB_DIR)
include_directories(${POSTGRES_SRC_DIR}/src/include ${CMAKE_CURRENT_SOURCE_DIR})

file(GLOB_RECURSE LLVM_JIT_SRC ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp ${CMAKE_CURRENT_SOURCE_DIR}/*.c)
list(REMOVE_ITEM LLVM_JIT_SRC ${CMAKE_CURRENT_SOURCE_DIR}/llvmjit_types.c)

add_library(llvmjit SHARED ${LLVM_JIT_SRC})
add_dependencies(llvmjit postgres)
SET_TARGET_PROPERTIES(llvmjit PROPERTIES PREFIX "")
target_link_libraries(llvmjit ${LLVM_LIBRARIES})
install(
				TARGETS llvmjit
				DESTINATION ${POSTGRES_LIB_DIR}
)

set(llvmjit_types_out ${CMAKE_CURRENT_BINARY_DIR}/llvmjit_types.bc)
set(LVMJIT_TYPES_SRC ${CMAKE_CURRENT_SOURCE_DIR}/llvmjit_types.c)



get_property(include_dirs DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY INCLUDE_DIRECTORIES)
foreach(INC_DIR ${include_dirs})
	if(${INC_DIR} MATCHES "^-I")
		list(APPEND _INCS ${INC_DIR})
	else()
		list(APPEND _INCS "-I${INC_DIR}")
	endif()
endforeach()


add_custom_command(OUTPUT ${llvmjit_types_out}
				COMMAND ${CMAKE_C_COMPILER} ${_INCS}
				-emit-llvm -c ${FLAGS}
				-o ${llvmjit_types_out}
				${LVMJIT_TYPES_SRC})

add_custom_target(comple_llvmjit_types ALL DEPENDS ${llvmjit_types_out})
install(
				FILES ${llvmjit_types_out}
				DESTINATION ${POSTGRES_LIB_DIR}
)



