/* pipe_client/pipe_client--1.0.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pipe_client" to load this file. \quit

CREATE OR REPLACE FUNCTION c60_server_pipe_params(client_lock_path cstring)
 RETURNS TABLE(shm_key integer, server_lock_path varchar, library_file_path varchar)
 AS 'MODULE_PATHNAME','c60_server_pipe_params'
 LANGUAGE C IMMUTABLE STRICT PARALLEL UNSAFE;
