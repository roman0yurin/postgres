find_program(PERL perl)

#Запускаем скрипты для генерации заголовчного кода из файлов с расширением .dat
FILE(GLOB DAT_HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/pg_*.dat)

add_custom_target(
				postgres_dat_gen
				COMMAND ${PERL} -I ${CMAKE_CURRENT_SOURCE_DIR}/../../backend/catalog ${CMAKE_CURRENT_SOURCE_DIR}/reformat_dat_file.pl -o ${CMAKE_CURRENT_SOURCE_DIR} ${DAT_HEADERS}
				COMMAND ${PERL} -I ${CMAKE_CURRENT_SOURCE_DIR}/../../backend/catalog ${CMAKE_CURRENT_SOURCE_DIR}/reformat_dat_file.pl -o ${CMAKE_CURRENT_SOURCE_DIR} ${DAT_HEADERS} --full-tuples
)