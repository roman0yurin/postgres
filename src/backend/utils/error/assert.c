/*-------------------------------------------------------------------------
 *
 * assert.c
 *	  Assert code.
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/backend/utils/error/assert.c
 *
 * NOTE
 *	  This should eventually work with elog()
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include <unistd.h>

extern void
ExceptionalConditionInternal(const char *conditionName,
							 const char *errorType,
							 const char *fileName,
							 int lineNumber) pg_attribute_noreturn();

/*
 * ExceptionalCondition - Handles the failure of an Assert()
 */
void
ExceptionalConditionInternal(const char *conditionName,
							 const char *errorType,
							 const char *fileName,
							 int lineNumber)
{
	if (!PointerIsValid(conditionName)
		|| !PointerIsValid(fileName)
		|| !PointerIsValid(errorType))
		write_stderr("TRAP: ExceptionalCondition: bad arguments\n");
	else
	{
		write_stderr("TRAP: %s(\"%s\", File: \"%s\", Line: %d)\n",
					 errorType, conditionName,
					 fileName, lineNumber);
	}

	/* Usually this shouldn't be needed, but make sure the msg went out */
	fflush(stderr);

#ifdef SLEEP_ON_ASSERT

	/*
	 * It would be nice to use pg_usleep() here, but only does 2000 sec or 33
	 * minutes, which seems too short.
	 */
	sleep(1000000);
#endif

	abort();
}

void (*ExceptionalConditionFunc)(const char*, const char*, const char*, int) pg_attribute_noreturn() = &ExceptionalConditionInternal;

void
ExceptionalCondition(const char *conditionName,
					 const char *errorType,
					 const char *fileName,
					 int lineNumber)
{
	(*ExceptionalConditionFunc)(conditionName, errorType, fileName, lineNumber);
}
