find_program(PERL perl)

#Запускаем скрипты для генерации заголовчного кода из файлов с расширением .dat
add_custom_target(
				postgres_dat_gen
				COMMAND ${PERL} -I ${CMAKE_CURRENT_SOURCE_DIR}/../../backend/catalog ${CMAKE_CURRENT_SOURCE_DIR}/reformat_dat_file.pl -o ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/pg_*.dat
				COMMAND ${PERL} -I ${CMAKE_CURRENT_SOURCE_DIR}/../../backend/catalog ${CMAKE_CURRENT_SOURCE_DIR}/reformat_dat_file.pl -o ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/pg_*.dat --full-tuples
)