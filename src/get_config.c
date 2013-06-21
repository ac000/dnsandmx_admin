/*
 * get_config.c
 *
 * Copyright (C) 	2012	OpenTech Labs
 *				Andrew Clayton <andrew@digital-domain.net>
 *			2013	DNSandMX
 *				Andrew Clayton <andrew@dnsandmx.com>
 *
 * Licensed under the GNU Affero General Public License version 3
 * See AGPL-3.0.txt
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dax_config.h"
#include "common.h"

int get_config(const char *filename)
{
	FILE *fp;
	char buf[BUF_SIZE];
	char *option;
	char *value;
	char *token;

	fp = fopen(filename, "r");
	if (!fp)
		return -1;

	while (fgets(buf, BUF_SIZE, fp)) {
		token = strtok(buf, "=");
		option = token;
		token = strtok(NULL, "=");
		value = token;
		/* Skip blank lines and comment lines beginning with a # */
		if (!value || option[0] == '#')
			continue;
		/* Loose the trailing \n */
		value[strlen(value) - 1] = '\0';

		if (strcmp(option, "SESSION_DB") == 0)
			rec_session_db = strdup(value);
		else if (strcmp(option, "APP_HOST") == 0)
			app_host = strdup(value);
		else if (strcmp(option, "WWW_HOST") == 0)
			www_host = strdup(value);
		else if (strcmp(option, "PRIMARY_NS") == 0)
			primary_ns = strdup(value);
		else if (strcmp(option, "SECONDARY_NS") == 0)
			secondary_ns = strdup(value);
		else if (strcmp(option, "PRIMARY_NS_IP") == 0)
			primary_ns_ip = strdup(value);
		else if (strcmp(option, "DB_USER") == 0)
			db_user = strdup(value);
		else if (strcmp(option, "DB_PASS") == 0)
			db_password = strdup(value);
		else if (strcmp(option, "DB_NAME") == 0)
			db_name = strdup(value);
		else if (strcmp(option, "DB_HOST") == 0)
			db_host = strdup(value);
		else if (strcmp(option, "DB_SHOST") == 0)
			db_shost = strdup(value);
		else if (strcmp(option, "DB_SOCKET_NAME") == 0)
			db_socket_name = strdup(value);
		else if (strcmp(option, "DB_PORT_NUM") == 0)
			db_port_num = atoi(value);
		else if (strcmp(option, "DB_FLAGS") == 0)
			db_flags = atoi(value);
		else if (strcmp(option, "MAIL_CMD") == 0)
			mail_cmd = strdup(value);
		else if (strcmp(option, "MAIL_FROM") == 0)
			mail_from = strdup(value);
		else if (strcmp(option, "MAIL_REPLY_TO") == 0)
			mail_reply_to = strdup(value);
		else if (strcmp(option, "LOG_DIR") == 0)
			log_dir = strdup(value);
		else if (strcmp(option, "NR_PROCS") == 0)
			nr_procs = atoi(value);
		else if (strcmp(option, "DEBUG_LEVEL") == 0)
			debug_level = atoi(value);
		else if (strcmp(option, "MULTI_TENANT") == 0)
			multi_tenant = atoi(value);
		else if (strcmp(option, "PAYPAL_BID") == 0)
			paypal_bid = strdup(value);
		else if (strcmp(option, "PAYPAL_REC_EMAIL") == 0)
			paypal_rec_email = strdup(value);
		else if (strcmp(option, "PAYPAL_HOST") == 0)
			paypal_host = strdup(value);
	}

	fclose(fp);

	return 0;
}
