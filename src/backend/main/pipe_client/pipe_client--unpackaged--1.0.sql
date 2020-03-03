/* pipe_client/pipe_client--unpackaged--1.0.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pipe_client FROM unpackaged" to load this file. \quit

ALTER EXTENSION refint ADD function c60_server_pipe_params();
