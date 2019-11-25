IF (WIN32)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-attributes -Wno-expansion-to-defined -fno-reorder-blocks-and-partition")
ENDIF()

include_directories(
	"${PROJECT_SOURCE_DIR}/src/include/libpq"
	"${PROJECT_SOURCE_DIR}/src/interfaces/libpq"
	"${PROJECT_SOURCE_DIR}/src/bin/pg_dump"
)

set(postgres_include_catalog "${PROJECT_SOURCE_DIR}/src/include/catalog")

set(FMGR_DATA
				${postgres_include_catalog}/pg_language.dat
				${postgres_include_catalog}/pg_proc.dat
)

set(gen_fmgrtab_depend
	utils/Gen_fmgrtab.pl
	${CMAKE_CURRENT_SOURCE_DIR}/catalog/Catalog.pm
	${postgres_include_catalog}/pg_proc.h
	${PROJECT_SOURCE_DIR}/src/include/access/transam.h
	${FMGR_DATA}
)

set(gen_fmgrtab_output
	${PROJECT_SOURCE_DIR}/src/include/utils/fmgroids.h
	${PROJECT_SOURCE_DIR}/src/include/utils/fmgrprotos.h
	${CMAKE_CURRENT_SOURCE_DIR}/utils/fmgrtab.c
)

add_custom_command(
	MAIN_DEPENDENCY ${gen_fmgrtab_depend}
	OUTPUT ${gen_fmgrtab_output}
	COMMAND ${PERL_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/catalog ${CMAKE_CURRENT_SOURCE_DIR}/utils/Gen_fmgrtab.pl --include-path=${PROJECT_SOURCE_DIR}/src/include ${FMGR_DATA}
	COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/utils/fmgroids.h ${PROJECT_SOURCE_DIR}/src/include/utils/fmgroids.h
	COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/utils/fmgrprotos.h ${PROJECT_SOURCE_DIR}/src/include/utils/fmgrprotos.h
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/utils
)

set(gen_probe_depend
	${CMAKE_CURRENT_SOURCE_DIR}/utils/Gen_dummy_probes.sed
	${CMAKE_CURRENT_SOURCE_DIR}/utils/probes.d
)

set(gen_probe_output
	${PROJECT_SOURCE_DIR}/src/include/utils/probes.h
)

add_custom_command(
	MAIN_DEPENDENCY ${gen_probe_depend}
	OUTPUT ${gen_probe_output}
	COMMAND ${SED_EXECUTABLE} -f Gen_dummy_probes.sed probes.d >  ${gen_probe_output}
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/utils
)

flex_target(GUC_SCANNER utils/misc/guc-file.l  "${CMAKE_CURRENT_SOURCE_DIR}/utils/misc/guc-file.c")
set_source_files_properties(utils/misc/guc.c PROPERTIES OBJECT_DEPENDS "${FLEX_GUC_SCANNER_OUTPUTS}")


#Need for bin/pg_xlogdump
set(access_rmgrdesc_SRC
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/brindesc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/clogdesc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/committsdesc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/dbasedesc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/genericdesc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/gindesc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/gistdesc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/hashdesc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/heapdesc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/logicalmsgdesc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/mxactdesc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/nbtdesc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/relmapdesc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/replorigindesc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/seqdesc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/smgrdesc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/spgdesc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/standbydesc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/tblspcdesc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/xactdesc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/xlogdesc.c
)

set(rmgrdesc_SRC
	${access_rmgrdesc_SRC}
	PARENT_SCOPE
)

set(access_brin_SRCS
	${CMAKE_CURRENT_SOURCE_DIR}/access/brin/brin.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/brin/brin_pageops.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/brin/brin_revmap.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/brin/brin_tuple.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/brin/brin_xlog.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/brin/brin_minmax.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/brin/brin_inclusion.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/brin/brin_validate.c
)

set(access_common_SRCS
	${CMAKE_CURRENT_SOURCE_DIR}/access/common/bufmask.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/common/heaptuple.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/common/indextuple.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/common/printsimple.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/common/printtup.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/common/relation.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/common/reloptions.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/common/scankey.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/common/session.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/common/tupconvert.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/common/tupdesc.c
)

set(access_gin_SRCS
	${CMAKE_CURRENT_SOURCE_DIR}/access/gin/ginutil.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/gin/gininsert.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/gin/ginxlog.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/gin/ginentrypage.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/gin/gindatapage.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/gin/ginbtree.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/gin/ginscan.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/gin/ginget.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/gin/ginvacuum.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/gin/ginarrayproc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/gin/ginbulk.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/gin/ginfast.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/gin/ginpostinglist.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/gin/ginlogic.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/gin/ginvalidate.c
)

set(access_gist_SRCS
	${CMAKE_CURRENT_SOURCE_DIR}/access/gist/gist.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/gist/gistutil.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/gist/gistxlog.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/gist/gistvacuum.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/gist/gistget.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/gist/gistscan.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/gist/gistproc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/gist/gistsplit.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/gist/gistbuild.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/gist/gistbuildbuffers.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/gist/gistvalidate.c
)

set(access_hash_SRCS
	${CMAKE_CURRENT_SOURCE_DIR}/access/hash/hash.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/hash/hashfunc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/hash/hashinsert.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/hash/hashovfl.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/hash/hashpage.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/hash/hashsearch.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/hash/hashsort.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/hash/hashutil.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/hash/hashvalidate.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/hash/hash_xlog.c
)

set(access_heap_SRCS
	${CMAKE_CURRENT_SOURCE_DIR}/access/heap/heapam.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/heap/heapam_handler.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/heap/heapam_visibility.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/heap/hio.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/heap/pruneheap.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/heap/rewriteheap.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/heap/syncscan.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/heap/tuptoaster.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/heap/vacuumlazy.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/heap/visibilitymap.c
)

set(access_index_SRCS
	${CMAKE_CURRENT_SOURCE_DIR}/access/index/amapi.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/index/amvalidate.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/index/genam.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/index/indexam.c
)

set(access_nbtree_SRCS
	${CMAKE_CURRENT_SOURCE_DIR}/access/nbtree/nbtcompare.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/nbtree/nbtinsert.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/nbtree/nbtpage.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/nbtree/nbtree.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/nbtree/nbtsearch.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/nbtree/nbtsplitloc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/nbtree/nbtutils.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/nbtree/nbtsort.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/nbtree/nbtvalidate.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/nbtree/nbtxlog.c
)

set(access_rmgrdesc_SRCS
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/brindesc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/clogdesc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/committsdesc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/dbasedesc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/genericdesc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/gindesc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/gistdesc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/hashdesc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/heapdesc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/logicalmsgdesc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/mxactdesc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/nbtdesc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/relmapdesc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/replorigindesc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/seqdesc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/smgrdesc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/spgdesc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/standbydesc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/tblspcdesc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/xactdesc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/rmgrdesc/xlogdesc.c
)

set(access_spgist_SRCS
	${CMAKE_CURRENT_SOURCE_DIR}/access/spgist/spgutils.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/spgist/spginsert.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/spgist/spgscan.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/spgist/spgvacuum.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/spgist/spgvalidate.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/spgist/spgdoinsert.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/spgist/spgxlog.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/spgist/spgtextproc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/spgist/spgquadtreeproc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/spgist/spgkdtreeproc.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/spgist/spgproc.c
)

set(access_table_SRCS
	${CMAKE_CURRENT_SOURCE_DIR}/access/table/table.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/table/tableam.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/table/tableamapi.c
)

set(access_tablesample_SRCS
	${CMAKE_CURRENT_SOURCE_DIR}/access/tablesample/bernoulli.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/tablesample/system.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/tablesample/tablesample.c
)

set(access_transam_SRCS
	${CMAKE_CURRENT_SOURCE_DIR}/access/transam/clog.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/transam/commit_ts.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/transam/generic_xlog.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/transam/multixact.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/transam/parallel.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/transam/rmgr.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/transam/slru.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/transam/subtrans.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/transam/timeline.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/transam/transam.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/transam/twophase.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/transam/twophase_rmgr.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/transam/varsup.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/transam/xact.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/transam/xlog.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/transam/xlogarchive.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/transam/xlogfuncs.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/transam/xloginsert.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/transam/xlogreader.c
	${CMAKE_CURRENT_SOURCE_DIR}/access/transam/xlogutils.c
)

set(access_SRCS
		${access_brin_SRCS}
		${access_common_SRCS}
		${access_gin_SRCS}
		${access_gist_SRCS}
		${access_hash_SRCS}
		${access_heap_SRCS}
		${access_index_SRCS}
		${access_nbtree_SRCS}
		${access_rmgrdesc_SRCS}
		${access_spgist_SRCS}
		${access_table_SRCS}
		${access_tablesample_SRCS}
		${access_transam_SRCS}
)

bison_target(BOOTSTRAP_PARSER bootstrap/bootparse.y ${CMAKE_CURRENT_SOURCE_DIR}/bootstrap/bootparse.c)
flex_target(BOOTSTRAP_SCANNER bootstrap/bootscanner.l  ${CMAKE_CURRENT_SOURCE_DIR}/bootstrap/bootscanner.c)
add_flex_bison_dependency(BOOTSTRAP_SCANNER BOOTSTRAP_PARSER)

set_source_files_properties(bootstrap/bootparse.c PROPERTIES OBJECT_DEPENDS ${FLEX_BOOTSTRAP_SCANNER_OUTPUTS})

set(bootstrap_SRCS
	bootstrap/bootstrap.c
	${BISON_BOOTSTRAP_PARSER_OUTPUTS}
)

set_source_files_properties(
	${BISON_BOOTSTRAP_PARSER_OUTPUTS}
	PROPERTIES GENERATED TRUE
)

set(POSTGRES_BKI_SRCS
	${postgres_include_catalog}/pg_proc.h
	${postgres_include_catalog}/pg_type.h
	${postgres_include_catalog}/pg_attribute.h
	${postgres_include_catalog}/pg_class.h
	${postgres_include_catalog}/pg_attrdef.h
	${postgres_include_catalog}/pg_constraint.h
	${postgres_include_catalog}/pg_inherits.h
	${postgres_include_catalog}/pg_index.h
	${postgres_include_catalog}/pg_operator.h
	${postgres_include_catalog}/pg_opfamily.h
	${postgres_include_catalog}/pg_opclass.h
	${postgres_include_catalog}/pg_am.h
	${postgres_include_catalog}/pg_amop.h
	${postgres_include_catalog}/pg_amproc.h
	${postgres_include_catalog}/pg_language.h
	${postgres_include_catalog}/pg_largeobject_metadata.h
	${postgres_include_catalog}/pg_largeobject.h
	${postgres_include_catalog}/pg_aggregate.h
	${postgres_include_catalog}/pg_statistic_ext.h
	${postgres_include_catalog}/pg_statistic_ext_data.h
	${postgres_include_catalog}/pg_statistic.h
	${postgres_include_catalog}/pg_rewrite.h
	${postgres_include_catalog}/pg_trigger.h
	${postgres_include_catalog}/pg_event_trigger.h
	${postgres_include_catalog}/pg_description.h
	${postgres_include_catalog}/pg_cast.h
	${postgres_include_catalog}/pg_enum.h
	${postgres_include_catalog}/pg_namespace.h
	${postgres_include_catalog}/pg_conversion.h
	${postgres_include_catalog}/pg_depend.h
	${postgres_include_catalog}/pg_database.h
	${postgres_include_catalog}/pg_db_role_setting.h
	${postgres_include_catalog}/pg_tablespace.h
	${postgres_include_catalog}/pg_pltemplate.h
	${postgres_include_catalog}/pg_authid.h
	${postgres_include_catalog}/pg_auth_members.h
	${postgres_include_catalog}/pg_shdepend.h
	${postgres_include_catalog}/pg_shdescription.h
	${postgres_include_catalog}/pg_ts_config.h
	${postgres_include_catalog}/pg_ts_config_map.h
	${postgres_include_catalog}/pg_ts_dict.h
	${postgres_include_catalog}/pg_ts_parser.h
	${postgres_include_catalog}/pg_ts_template.h
	${postgres_include_catalog}/pg_extension.h
	${postgres_include_catalog}/pg_foreign_data_wrapper.h
	${postgres_include_catalog}/pg_foreign_server.h
	${postgres_include_catalog}/pg_user_mapping.h
	${postgres_include_catalog}/pg_foreign_table.h
	${postgres_include_catalog}/pg_policy.h
	${postgres_include_catalog}/pg_replication_origin.h
	${postgres_include_catalog}/pg_default_acl.h
	${postgres_include_catalog}/pg_init_privs.h
	${postgres_include_catalog}/pg_seclabel.h
	${postgres_include_catalog}/pg_shseclabel.h
	${postgres_include_catalog}/pg_collation.h
	${postgres_include_catalog}/pg_partitioned_table.h
	${postgres_include_catalog}/pg_range.h
	${postgres_include_catalog}/pg_transform.h
	${postgres_include_catalog}/pg_sequence.h
	${postgres_include_catalog}/pg_publication.h
	${postgres_include_catalog}/pg_publication_rel.h
	${postgres_include_catalog}/pg_subscription.h
	${postgres_include_catalog}/pg_subscription_rel.h
	${postgres_include_catalog}/toasting.h
	${postgres_include_catalog}/indexing.h
)


# The .dat files we need can just be listed alphabetically.
file(GLOB_RECURSE POSTGRES_BKI_DATA ${postgres_include_catalog}/*.dat)

set(catalog_SRCS
	catalog/catalog.c
	catalog/dependency.c
	catalog/heap.c
	catalog/index.c
	catalog/indexing.c
	catalog/namespace.c
	catalog/aclchk.c
	catalog/objectaccess.c
	catalog/objectaddress.c
	catalog/pg_aggregate.c
	catalog/pg_collation.c
	catalog/pg_constraint.c
	catalog/pg_conversion.c
	catalog/pg_depend.c
	catalog/pg_enum.c
	catalog/pg_inherits.c
	catalog/pg_largeobject.c
	catalog/pg_namespace.c
	catalog/pg_operator.c
	catalog/pg_proc.c
	catalog/pg_publication.c
	catalog/pg_subscription.c
	catalog/pg_range.c
	catalog/pg_db_role_setting.c
	catalog/pg_shdepend.c
	catalog/pg_type.c
	catalog/storage.c
	catalog/toasting.c
	catalog/partition.c
)

set(catalog_include
	"-I${PROJECT_SOURCE_DIR}/src/backend/catalog"
	"-I${PROJECT_SOURCE_DIR}/src/include/catalog"
)


add_custom_command(
				OUTPUT catalog/postgres.bki
				COMMAND ${PERL_EXECUTABLE} -I${CMAKE_CURRENT_SOURCE_DIR}/catalog genbki.pl --set-version=${POSTGRES_MAJOR_VERSION} ${POSTGRES_BKI_SRCS}
				COMMAND ${CMAKE_COMMAND} -E copy schemapg.h ${PROJECT_SOURCE_DIR}/src/include/catalog/schemapg.h
				WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/catalog
)

set(ADDITIONAL_GENERATIONS )
if(WIN32)
	set(ADDITIONAL_GENERATIONS ${ADDITIONAL_GENERATIONS} generateTimezoneConfigs)
endif()

##Генерация исходников через Perl. При разработке выывается вручную, так как add_custom_target с DEPENDENCY будет делать перегенерацию каждый раз, а add_custom_command работает только в пределах одного CMAKE файла
add_custom_target(
		POSTGRES_GENERATE_SRC
		DEPENDS ${POSTGRES_BKI_SRCS} ${POSTGRES_BKI_DATA} postgres_dat_gen ${ADDITIONAL_GENERATIONS}
		COMMAND ${PERL_EXECUTABLE} genbki.pl --include-path=${CMAKE_CURRENT_SOURCE_DIR}/../include/ --set-version=${POSTGRES_MAJOR_VERSION} ${POSTGRES_BKI_SRCS}
		COMMAND ${CMAKE_COMMAND} -E copy schemapg.h ${PROJECT_SOURCE_DIR}/src/include/catalog/schemapg.h
		COMMAND mv ${CMAKE_CURRENT_SOURCE_DIR}/catalog/*_d.h ${PROJECT_SOURCE_DIR}/src/include/catalog
		COMMAND ${PERL_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/../tools ${CMAKE_CURRENT_SOURCE_DIR}/../tools/gen_keywordlist.pl --extern -o ${CMAKE_CURRENT_SOURCE_DIR}/../common ${CMAKE_CURRENT_SOURCE_DIR}/../include/parser/kwlist.h
		WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/catalog
)


set(commands_SRCS
	commands/aggregatecmds.c
	commands/alter.c
	commands/analyze.c
	commands/async.c
	commands/amcmds.c
	commands/cluster.c
	commands/comment.c
	commands/collationcmds.c
	commands/constraint.c
	commands/conversioncmds.c
	commands/copy.c
	commands/createas.c
	commands/dbcommands.c
	commands/define.c
	commands/discard.c
	commands/dropcmds.c
	commands/event_trigger.c
	commands/explain.c
	commands/extension.c
	commands/foreigncmds.c
	commands/functioncmds.c
	commands/indexcmds.c
	commands/lockcmds.c
	commands/matview.c
	commands/operatorcmds.c
	commands/opclasscmds.c
	commands/policy.c
	commands/portalcmds.c
	commands/prepare.c
	commands/proclang.c
	commands/publicationcmds.c
	commands/schemacmds.c
	commands/seclabel.c
	commands/sequence.c
	commands/statscmds.c
	commands/subscriptioncmds.c
	commands/tablecmds.c
	commands/tablespace.c
	commands/trigger.c
	commands/tsearchcmds.c
	commands/typecmds.c
	commands/user.c
	commands/vacuum.c
	commands/variable.c
	commands/view.c
)

file(GLOB_RECURSE executor_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/executor/*.c)

file(GLOB_RECURSE lib_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/lib/*.c)

if(OPENSSL_FOUND)
	set(libpq_ssl_SRCS libpq/be-secure-openssl.c)
endif(OPENSSL_FOUND)

set(libpq_SRCS
	libpq/be-fsstubs.c
	libpq/be-secure.c
	libpq/auth.c
	libpq/crypt.c
	libpq/hba.c
	libpq/pqcomm.c
	libpq/pqformat.c
	libpq/pqmq.c
	libpq/pqsignal.c
	libpq/ifaddr.c
	libpq/auth-scram.c
	${libpq_ssl_SRCS}
)

bison_target(JSON_GRAM
		utils/adt/jsonpath_gram.y
		${CMAKE_CURRENT_SOURCE_DIR}/utils/adt/jsonpath_gram.c
)

flex_target(JSON_SCAN
		utils/adt/jsonpath_scan.l
		${CMAKE_CURRENT_SOURCE_DIR}/utils/adt/jsonpath_scan.c
		COMPILE_FLAGS "-b -CF -p -p"
)

add_flex_bison_dependency(JSON_SCAN JSON_GRAM)

set_source_files_properties(utils/adt/jsonpath.c PROPERTIES OBJECT_DEPENDS "${FLEX_JSON_SCAN_OUTPUTS};${BISON_JSON_GRAM_OUTPUTS}")

file(GLOB_RECURSE utils_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/utils/*.c)

file(GLOB_RECURSE utils_conversion_procs_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/utils/mb/conversion_procs/*.c)
list(REMOVE_ITEM utils_SRCS
				${CMAKE_CURRENT_SOURCE_DIR}/utils/adt/levenshtein.c
				${CMAKE_CURRENT_SOURCE_DIR}/utils/adt/like_match.c
				${CMAKE_CURRENT_SOURCE_DIR}/utils/adt/jsonpath_gram.c
				${CMAKE_CURRENT_SOURCE_DIR}/utils/adt/jsonpath_scan.c
				${CMAKE_CURRENT_SOURCE_DIR}/utils/sort/qsort_tuple.c
				${CMAKE_CURRENT_SOURCE_DIR}/utils/misc/guc-file.c
				${CMAKE_CURRENT_SOURCE_DIR}/utils/mb/iso.c
				${CMAKE_CURRENT_SOURCE_DIR}/utils/mb/win866.c
				${CMAKE_CURRENT_SOURCE_DIR}/utils/mb/win1251.c
				${utils_conversion_procs_SRCS}
)
list(APPEND utils_SRCS ${gen_fmgrtab_output} ${gen_probe_output} ${BISON_JSON_GRAM_OUTPUTS})

set(nodes_SRCS
	nodes/nodeFuncs.c
	nodes/nodes.c
	nodes/list.c
	nodes/bitmapset.c
	nodes/tidbitmap.c
	nodes/copyfuncs.c
	nodes/equalfuncs.c
	nodes/makefuncs.c
	nodes/outfuncs.c
	nodes/readfuncs.c
	nodes/print.c
	nodes/read.c
	nodes/params.c
	nodes/value.c
	nodes/extensible.c
)

set(optimizer_SRCS
	optimizer/geqo/geqo_copy.c
	optimizer/geqo/geqo_eval.c
	optimizer/geqo/geqo_main.c
	optimizer/geqo/geqo_misc.c
	optimizer/geqo/geqo_mutation.c
	optimizer/geqo/geqo_pool.c
	optimizer/geqo/geqo_random.c
	optimizer/geqo/geqo_recombination.c
	optimizer/geqo/geqo_selection.c
	optimizer/geqo/geqo_erx.c
	optimizer/geqo/geqo_pmx.c
	optimizer/geqo/geqo_cx.c
	optimizer/geqo/geqo_px.c
	optimizer/geqo/geqo_ox1.c
	optimizer/geqo/geqo_ox2.c
	optimizer/path/allpaths.c
	optimizer/path/clausesel.c
	optimizer/path/costsize.c
	optimizer/path/equivclass.c
	optimizer/path/indxpath.c
	optimizer/path/joinpath.c
	optimizer/path/joinrels.c
	optimizer/path/pathkeys.c
	optimizer/path/tidpath.c
	optimizer/plan/analyzejoins.c
	optimizer/plan/createplan.c
	optimizer/plan/initsplan.c
	optimizer/plan/planagg.c
	optimizer/plan/planmain.c
	optimizer/plan/planner.c
	optimizer/plan/setrefs.c
	optimizer/plan/subselect.c
	optimizer/prep/prepjointree.c
	optimizer/prep/prepqual.c
	optimizer/prep/preptlist.c
	optimizer/prep/prepunion.c
	optimizer/util/appendinfo.c
	optimizer/util/clauses.c
	optimizer/util/inherit.c
	optimizer/util/joininfo.c
	optimizer/util/orclauses.c
	optimizer/util/paramassign.c
	optimizer/util/pathnode.c
	optimizer/util/placeholder.c
	optimizer/util/plancat.c
	optimizer/util/predtest.c
	optimizer/util/relnode.c
	optimizer/util/restrictinfo.c
	optimizer/util/tlist.c
	optimizer/util/var.c
)

set(rewrite_SRCS
	rewrite/rewriteRemove.c
	rewrite/rewriteDefine.c
	rewrite/rewriteHandler.c
	rewrite/rewriteManip.c
	rewrite/rewriteSupport.c
	rewrite/rowsecurity.c
)

set(parser_SRCS
	parser/analyze.c
	#parser/gram.c
	parser/parser.c
	parser/parse_agg.c
	parser/parse_clause.c
	parser/parse_coerce.c
	parser/parse_collate.c
	parser/parse_cte.c
	parser/parse_expr.c
	parser/parse_func.c
	parser/parse_node.c
	parser/parse_oper.c
	parser/parse_param.c
	parser/parse_relation.c
	parser/parse_target.c
	parser/parse_type.c
	parser/parse_utilcmd.c
	parser/parse_enr.c
	parser/scansup.c
	${PROJECT_SOURCE_DIR}/src/backend/parser/gram.c
	${PROJECT_SOURCE_DIR}/src/backend/parser/scan.c
)

set_source_files_properties(
	${PROJECT_SOURCE_DIR}/src/backend/parser/gram.c
	${PROJECT_SOURCE_DIR}/src/backend/parser/scan.c
	PROPERTIES GENERATED TRUE
)

set(tcop_SRCS
	tcop/dest.c
	tcop/fastpath.c
	tcop/postgres.c
	tcop/pquery.c
	tcop/utility.c
)

set(tsearch_SRCS
	tsearch/ts_locale.c
	tsearch/ts_parse.c
	tsearch/wparser.c
	tsearch/wparser_def.c
	tsearch/dict.c
	tsearch/dict_simple.c
	tsearch/dict_synonym.c
	tsearch/dict_thesaurus.c
	tsearch/dict_ispell.c
	tsearch/regis.c
	tsearch/spell.c
	tsearch/to_tsany.c
	tsearch/ts_selfuncs.c
	tsearch/ts_typanalyze.c
	tsearch/ts_utils.c
)

install(FILES
			tsearch/dicts/ispell_sample.dict
			tsearch/dicts/ispell_sample.affix
			tsearch/dicts/hunspell_sample.affix
			tsearch/dicts/hunspell_sample_long.affix
			tsearch/dicts/hunspell_sample_long.dict
			tsearch/dicts/hunspell_sample_num.affix
			tsearch/dicts/hunspell_sample_num.dict
			tsearch/dicts/synonym_sample.syn
			tsearch/dicts/thesaurus_sample.ths
		DESTINATION ${PGSHAREDIR}/tsearch_data)

set(regex_SRCS
	regex/regcomp.c
	regex/regerror.c
	regex/regexec.c
	regex/regfree.c
	regex/regprefix.c
	regex/regexport.c
)

set(postmaster_SRCS
	postmaster/autovacuum.c
	postmaster/bgworker.c
	postmaster/bgwriter.c
	postmaster/checkpointer.c
	postmaster/fork_process.c
	postmaster/pgarch.c
	postmaster/pgstat.c
	postmaster/postmaster.c
	postmaster/startup.c
	postmaster/syslogger.c
	postmaster/walwriter.c
)

if(WIN32 OR CYGWIN OR MINGW)
	set(backend_port_win32_SRC
		port/win32/timer.c
		port/win32/socket.c
		port/win32/signal.c
		# I hope it is not necessary for modern MinGW
		#port/win32/mingwcompat.c
		port/win32/crashdump.c
	)
	if(NAVE_MINIDUMP_TYPE)
		set(backend_port_win32_SRC
			${backend_port_win32_SRC}
			port/win32/crashdump.c
		)
	endif(NAVE_MINIDUMP_TYPE)
endif()

set(backend_port_SRCS
	port/atomics.c
	port/tas/${TAS}
	${backend_port_win32_SRC}
	${backend_port_darwin_SRC}
	${dynloader_SRCS}
	${SEMA_IMPLEMENTATION}
	${SHMEM_IMPLEMENTATION}
)

file(GLOB_RECURSE storage_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/storage/*.c)

if(NOT MSVC)
	set_source_files_properties(storage/page/checksum.c
		PROPERTIES COMPILE_FLAGS ${CFLAGS_VECTOR})
endif()
bison_target(REPL_GRAM
	replication/repl_gram.y
	${CMAKE_CURRENT_SOURCE_DIR}/replication/repl_gram.c
)
flex_target(REPL_SCAN
	replication/repl_scanner.l
	${CMAKE_CURRENT_SOURCE_DIR}/replication/repl_scanner.c
)
set_source_files_properties(${BISON_REPL_GRAM_OUTPUTS}
	PROPERTIES OBJECT_DEPENDS ${FLEX_REPL_SCAN_OUTPUTS})

bison_target(SYNC_GRAM
	replication/syncrep_gram.y
	${CMAKE_CURRENT_SOURCE_DIR}/replication/syncrep_gram.c
)
flex_target(SYNC_SCAN
	replication/syncrep_scanner.l
	${CMAKE_CURRENT_SOURCE_DIR}/replication/syncrep_scanner.c
)
set_source_files_properties(${BISON_SYNC_GRAM_OUTPUTS}
	PROPERTIES OBJECT_DEPENDS ${FLEX_SYNC_SCAN_OUTPUTS})


set(replication_SRCS
	replication/walsender.c
	replication/walreceiverfuncs.c
	replication/walreceiver.c
	replication/basebackup.c
	replication/slot.c
	replication/slotfuncs.c
	replication/syncrep.c
	replication/logical/decode.c
	replication/logical/logical.c
	replication/logical/logicalfuncs.c
	replication/logical/reorderbuffer.c
	replication/logical/origin.c
	replication/logical/snapbuild.c
	replication/logical/message.c
	replication/logical/launcher.c
	replication/logical/proto.c
	replication/logical/relation.c
	replication/logical/tablesync.c
	replication/logical/worker.c

	${BISON_REPL_GRAM_OUTPUTS}
	${BISON_SYNC_GRAM_OUTPUTS}
)

set(timezone_SRCS
	${PROJECT_SOURCE_DIR}/src/timezone/localtime.c
	${PROJECT_SOURCE_DIR}/src/timezone/strftime.c
	${PROJECT_SOURCE_DIR}/src/timezone/pgtz.c
)

set(statistics_SRCS
	statistics/extended_stats.c
	statistics/dependencies.c
	statistics/mcv.c
	statistics/mvdistinct.c
)

add_custom_command(
	OUTPUT "${PROJECT_SOURCE_DIR}/src/backend/utils/sort/qsort_tuple.c"
	#MAIN_DEPENDENCY gen_qsort_tuple.pl
	COMMAND ${PERL_EXECUTABLE} "gen_qsort_tuple.pl" > "${PROJECT_SOURCE_DIR}/src/backend/utils/sort/qsort_tuple.c"
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/utils/sort
)

set_source_files_properties(utils/sort/tuplesort.c
	PROPERTIES OBJECT_DEPENDS "${PROJECT_SOURCE_DIR}/src/backend/utils/sort/qsort_tuple.c")

file(GLOB JIT_SRC jit/*.c jit/*.cpp)
file(GLOB_RECURSE PART_SRC partitioning/*.c)

set(postgres_core_SRCS
	${access_SRCS}
	${storage_SRCS}
	${bootstrap_SRCS}
	${commands_SRCS}
	${catalog_SRCS}
	${executor_SRCS}
	foreign/foreign.c
	${utils_SRCS}
	${lib_SRCS}
	${libpq_SRCS}
	${nodes_SRCS}
	${optimizer_SRCS}
	${rewrite_SRCS}
	${parser_SRCS}
	${tcop_SRCS}
	${tsearch_SRCS}
	${regex_SRCS}
	${postmaster_SRCS}
	${backend_port_SRCS}
	${replication_SRCS}
	${timezone_SRCS}
	${statistics_SRCS}
	${JIT_SRC}
	${PART_SRC}
)

set(postgres_SRCS
	${postgres_core_SRCS}
	main/main.c
)

if(OPENSSL_FOUND)
	include_directories(BEFORE	${OPENSSL_INCLUDE_DIR})
endif()
if(LIBXML2_FOUND)
	include_directories(BEFORE	${LIBXML2_INCLUDE_DIR})
endif()
if(ICU_FOUND)
	include_directories(BEFORE	${ICU_INCLUDE_DIRS})
endif()
#include_directories(BEFORE
#	${OPENSSL_INCLUDE_DIR}
#	${LIBXML2_INCLUDE_DIR}
#)

if(MSVC)
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /STACK:${WIN32_STACK_RLIMIT}")
endif()

if(MINGW OR CYGWIN)
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--stack,${WIN32_STACK_RLIMIT} -Wl,--export-all-symbols")
endif()

add_library(postgres_core SHARED ${postgres_core_SRCS})

add_executable(postgres
	main/main.c
)

add_executable(postgres_sgaz
	main/main_sgaz.c
	main/memory_socket.cpp
)

target_link_libraries(postgres
	postgres_core
	pq
	pgcommon_srv
	pgport_srv
	${READLINE_LIBRARY}
	${CMAKE_THREAD_LIBS_INIT}
	${DL_LIBRARIES}
	${LIB_M}
	${GSS_LIBS}
	${ICU_LIBRARIES}
	${LLVM_LIBRARIES}
)

target_link_libraries(postgres_sgaz
	postgres_core
	pq
	pgcommon_srv
	pgport_srv
	${READLINE_LIBRARY}
	${CMAKE_THREAD_LIBS_INIT}
	${DL_LIBRARIES}
	${LIB_M}
	${GSS_LIBS}
	${ICU_LIBRARIES}
	${LLVM_LIBRARIES}
)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
	target_compile_definitions(postgres_core PRIVATE -DEXEC_BACKEND)
	target_compile_definitions(postgres PRIVATE -DEXEC_BACKEND)
	target_compile_definitions(postgres_sgaz PRIVATE -DEXEC_BACKEND)
endif()

if(USE_SYSTEMD)
	target_link_libraries(postgres systemd)
#	target_link_libraries(postgres_sgaz systemd)
endif()

if(OPENSSL_FOUND)
	target_link_libraries(postgres ${OPENSSL_LIBRARIES})
	target_link_libraries(postgres_sgaz ${OPENSSL_LIBRARIES})
endif()


if(DBGHELP_FOUND)
	target_link_libraries(postgres ${DBGHELP_LIBRARIES})
	target_link_libraries(postgres_sgaz ${DBGHELP_LIBRARIES})
elseif(DEFINED ENV{MINGW64_PROJ_ROOT})
	target_link_libraries(postgres "$ENV{MINGW64_PROJ_ROOT}/mingw64/x86_64-w64-mingw32/lib/libdbghelp.a")
	target_link_libraries(postgres_sgaz "$ENV{MINGW64_PROJ_ROOT}/mingw64/x86_64-w64-mingw32/lib/libdbghelp.a")
endif()

if(LIBXML2_FOUND)
	target_link_libraries(postgres ${LIBXML2_LIBRARIES})
	target_link_libraries(postgres_sgaz ${LIBXML2_LIBRARIES})
endif()

if(USE_PAM)
	target_link_libraries(postgres ${PAM_LIB})
	target_link_libraries(postgres_sgaz ${PAM_LIB})
endif()

if(LDAP_FOUND)
	target_link_libraries(postgres ${LBER_LIBRARIES})
	target_link_libraries(postgres_sgaz ${LBER_LIBRARIES})
endif()

add_dependencies(postgres_core gen_errorcodes generate_parser_gram_h)

if(UNIX AND NOT APPLE)
	target_link_libraries(postgres rt)
	target_link_libraries(postgres_sgaz rt)
endif()


target_compile_definitions(postgres_core PRIVATE -DPG_KRB_SRVTAB="${PG_KRB_SRVTAB}")
target_compile_definitions(postgres PRIVATE -DPG_KRB_SRVTAB="${PG_KRB_SRVTAB}")
target_compile_definitions(postgres_sgaz PRIVATE -DPG_KRB_SRVTAB="${PG_KRB_SRVTAB}")

if(WIN32)
	target_compile_definitions(postgres PRIVATE -DBUILDING_DLL -DEXEC_BACKEND)
endif()

if(MINGW)
	set_target_properties(postgres PROPERTIES LINK_FLAGS -Wl,--out-implib=libpostgres.dll.a)
endif()

set_target_properties(postgres PROPERTIES ENABLE_EXPORTS 1)
set_target_properties(postgres PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
#Realy need?
add_custom_target(duplicate_oids
	COMMAND ${PERL_EXECUTABLE} ./duplicate_oids
	WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src/include/catalog
)

add_library(pqwalreceiver ${PLUGIN_TYPE}
	${PROJECT_SOURCE_DIR}/src/include/utils/fmgrprotos.h
	replication/libpqwalreceiver/libpqwalreceiver.c
	${backend_port_win32_SRC}
	${backend_port_darwin_SRC}
)
set_target_properties(pqwalreceiver PROPERTIES PREFIX "lib")

add_library(pgoutput ${PLUGIN_TYPE}
	replication/pgoutput/pgoutput.c
	${backend_port_win32_SRC}
	${backend_port_darwin_SRC}
)

if(MSVC)
	gen_def(pqwalreceiver)
	gen_def(pgoutput)
	gen_def(postgres)
endif()

if(WIN32)
	target_link_libraries(pqwalreceiver postgres)
	target_link_libraries(pgoutput postgres)
endif()

#Strange logic
if(MINGW)
	target_compile_definitions(pqwalreceiver PRIVATE -DBUILDING_DLL)
	target_compile_definitions(pgoutput PRIVATE -DBUILDING_DLL)
endif()

target_link_libraries(pqwalreceiver pq)
target_link_libraries(pgoutput pq)

install(TARGETS postgres pqwalreceiver
		RUNTIME DESTINATION ${PGBINDIR}
		LIBRARY DESTINATION ${LIBDIR})

install(TARGETS postgres pgoutput
		RUNTIME DESTINATION ${PGBINDIR}
		LIBRARY DESTINATION ${LIBDIR})

install(FILES
	catalog/postgres.bki
	catalog/postgres.description
	catalog/postgres.shdescription
	catalog/information_schema.sql
	catalog/sql_features.txt
	catalog/system_views.sql
	libpq/pg_hba.conf.sample
	libpq/pg_ident.conf.sample
	${CMAKE_CURRENT_BINARY_DIR}/utils/misc/postgresql.conf.sample
DESTINATION ${PGSHAREDIR})

install(TARGETS postgres_core
		LIBRARY DESTINATION ${LIBDIR})

install(TARGETS postgres postgres_sgaz
		RUNTIME DESTINATION ${PGBINDIR}
		LIBRARY DESTINATION ${LIBDIR})

set(PG_IO_CONCURRENCY 4)
if(WIN32)
	set(PG_IO_CONCURRENCY 0)
endif()
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/utils/misc/postgresql.conf.sample ${CMAKE_CURRENT_BINARY_DIR}/utils/misc/postgresql.conf.sample)
add_subdirectory(utils/mb/conversion_procs)
add_subdirectory(snowball)
if(NOT WIN32)
	add_subdirectory(jit/llvm)
endif()

if(ENABLE_NLS)
	MAKE_MO(postgres "de;es;fr;id;it;ja;pl;pt_BR;ru;zh_CN;ko")
endif()
