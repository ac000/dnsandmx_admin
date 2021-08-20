/*
 * db.h
 *
 * Copyright (C) 2012 - 2013	OpenTech Labs
 *				Andrew Clayton <andrew@digital-domain.net>
 *			2013	DNSandMX
 *				Andrew Clayton <andrew@dnsandmx.com>
 *
 * Licensed under the GNU Affero General Public License version 3
 * See AGPL-3.0.txt
 */

#ifndef _DB_H_
#define _DB_H_

/* For Tokyocabinet (user sessions) */
#include <tcutil.h>
#include <tctdb.h>
#include <stdbool.h>
#include <stdint.h>
#include <libgen.h>

/* MySQL */
#include <mysql.h>
#include <mysqld_error.h>

/*
 * Wrapper around mysql_real_query(), it uses __sql_query() to do the
 * actual work. It takes a mysql connection and a query string and passes
 * that to __sql_query() along with the function name of the caller for the
 * sql log.
 */
#define sql_query(conn, fmt, ...) \
	__sql_query(conn, (const char *)__func__, fmt, ##__VA_ARGS__)

extern MYSQL *conn;

MYSQL *db_conn(const char *host, const char *db, bool ssl);
MYSQL_RES *__sql_query(MYSQL *conn, const char *func, const char *fmt, ...);

#endif /* _DB_H_ */
