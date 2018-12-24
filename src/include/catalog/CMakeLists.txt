find_program(PERL perl)

set(CATALOG_DAT_GEN_OUT ${CMAKE_CURRENT_SOURCE_DIR}/pg_language.dat ${CMAKE_CURRENT_SOURCE_DIR}/pg_opclass.dat ${CMAKE_CURRENT_SOURCE_DIR}/pg_operator.dat ${CMAKE_CURRENT_SOURCE_DIR}/pg_proc.dat)

#Запускаем скрипты для генерации заголовчного кода из файлов с расширением .dat
add_custom_command(
				OUTPUT ${CATALOG_DAT_GEN_OUT}
				catalog_dat_gen
				COMMAND ${PERL} -I ${CMAKE_CURRENT_SOURCE_DIR}/../../backend/catalog ${CMAKE_CURRENT_SOURCE_DIR}/reformat_dat_file.pl -o ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/pg_*.dat
				COMMAND ${PERL} -I ${CMAKE_CURRENT_SOURCE_DIR}/../../backend/catalog ${CMAKE_CURRENT_SOURCE_DIR}/reformat_dat_file.pl -o ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/pg_*.dat --full-tuples
)