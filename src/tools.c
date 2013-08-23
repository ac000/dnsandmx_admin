/*
 * tools.c - Functions for the various actions under /tools/
 *
 * Copyright (C) 2013		DNSandMX
 * 				Andrew Clayton <andrew@dnsandmx.com>
 *
 * Licensed under the GNU Affero General Public License version 3
 * See AGPL-3.0.txt
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

#include <glib.h>

#include "common.h"

void dump_dns_domain_to_bind(int domain_id)
{
	unsigned long i;
	unsigned long nr_rows;
	size_t size;
	FILE *out;
	MYSQL_RES *res;
	MYSQL_ROW row;
	GHashTable *db_row = NULL;
	gchar **soa_bits;
	char *ptr;
	char *domain;
	const char *def_ttl;

	res = sql_query(conn, "SELECT domain_id FROM domains WHERE uid = %d "
			"AND domain_id = %d", user_session.uid, domain_id);
	if (mysql_num_rows(res) == 0) {
		fcgx_p("Location: /tools/\r\n\r\n");
		goto out;
	}
	mysql_free_result(res);

	res = sql_query(conn, "SELECT name FROM pdns.domains WHERE id = %d",
			domain_id);
	row = mysql_fetch_row(res);
	domain = strdupa(row[0]);
	mysql_free_result(res);

	out = open_memstream(&ptr, &size);
	res = sql_query(conn, "SELECT TRIM(LEADING '!!' FROM "
			"TRIM(TRAILING '%s' FROM name)) AS name, type, "
			"content, ttl, prio, change_date FROM pdns.records "
			"WHERE domain_id = %d", domain, domain_id);
	/* Create the SOA record */
	db_row = get_dbrow(res);
	def_ttl = strdupa(get_var(db_row, "ttl"));
	fprintf(out, "$TTL %s\n", def_ttl);
	soa_bits = g_strsplit(get_var(db_row, "content"), " ", 0);
	fprintf(out, "@\tIN\tSOA\t%s%s %s%s {\n",
		soa_bits[0],
		(soa_bits[0][strlen(soa_bits[0]) - 1] == '.') ? "" : ".",
		soa_bits[1],
		(soa_bits[1][strlen(soa_bits[1]) - 1] == '.') ? "" : ".");
	if (strcmp(soa_bits[2], "0") == 0) {
		/*
		 * PowerDNS uses a serial of 0 in the SOA record for
		 * domains it's the primary server for and instead
		 * uses the change_date field of the records table as
		 * a serial.
		 *
		 * Convert this into the format YYYYMMDDNN
		 */
		time_t t = strtoll(get_var(db_row, "change_date"), NULL, 10);
		struct tm *tm = gmtime(&t);

		fprintf(out, "\t\t\t%04d%02d%02d00\n", tm->tm_year + 1900,
				tm->tm_mon + 1, tm->tm_mday);
	} else {
		fprintf(out, "\t\t\t%s\n", soa_bits[2]);
	}
	fprintf(out, "\t\t\t%s\n", soa_bits[3]);
	fprintf(out, "\t\t\t%s\n", soa_bits[4]);
	fprintf(out, "\t\t\t%s\n", soa_bits[5]);
	fprintf(out, "\t\t\t%s }\n", soa_bits[6]);
	g_strfreev(soa_bits);
	free_vars(db_row);

	nr_rows = mysql_num_rows(res);
	for (i = 1; i < nr_rows; i++) {
		const char *type;
		const char *content;
		const char *ttl;
		const char *prio;
		char *name;
		bool disp_name = true;

		db_row = get_dbrow(res);
		type = get_var(db_row, "type");
		content = get_var(db_row, "content");
		ttl = get_var(db_row, "ttl");
		prio = get_var(db_row, "prio");
		name = (char *)get_var(db_row, "name");
		/* Loose the trailing '.' */
		name[strlen(name) - 1] = '\0';

		if (strcmp(type, "NS") == 0 || strcmp(type, "MX") == 0)
			disp_name = false;

		fprintf(out, "%s\t\t%s IN %s %s\t\t%s%s\n",
				(disp_name) ? name : "",
				(strcmp(ttl, def_ttl) == 0) ? "" : ttl,
				type,
				(strcmp(type, "MX") == 0) ? prio : "",
				content,
				(strcmp(type, "CNAME") == 0 ||
				 strcmp(type, "MX") == 0 ||
				 strcmp(type, "NS") == 0) ? "." : "");
		free_vars(db_row);
	}
	fclose(out);

	fcgx_p("Content-Type: text/plain\r\n");
	fcgx_p("Content-Length: %ld\r\n", size);
	fcgx_p("Content-Disposition: attachment; filename = %s.zone\r\n",
			domain);
	fcgx_p("\r\n");
	fcgx_p("%s", ptr);

	free(ptr);

out:
	mysql_free_result(res);
}
