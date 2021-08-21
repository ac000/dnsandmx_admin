/*
 * config.c
 *
 * Copyright (C) 	2012	OpenTech Labs
 *				Andrew Clayton <andrew@digital-domain.net>
 *			2013	DNSandMX
 *				Andrew Clayton <andrew@dnsandmx.com>
 *
 * Licensed under the GNU Affero General Public License version 3
 * See AGPL-3.0.txt
 */

#define _GNU_SOURCE	1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "common.h"

static void set_defaults(struct cfg *cfg)
{
	if (!cfg->log_dir)
		cfg->log_dir = strdup(CFG_DEF_LOG_DIR);
	if (!cfg->db_host)
		cfg->db_host = strdup(CFG_DEF_DB_HOST);
	if (cfg->db_port_num == 0)
		cfg->db_port_num = CFG_DEF_DB_PORT_NUM;
}

const struct cfg *get_config(const char *filename)
{
	FILE *fp;
	char buf[BUF_SIZE];
	struct cfg *c;

	fp = fopen(filename, "r");
	if (!fp)
		return NULL;

	c = calloc(1, sizeof(struct cfg));

	while (fgets(buf, BUF_SIZE, fp)) {
		char *token = strtok(buf, "=");
		char *option = token;
		char *value;

		token = strtok(NULL, "=");
		value = token;
		/* Skip blank lines and comment lines beginning with a # */
		if (!value || option[0] == '#')
			continue;
		/* Loose the trailing \n */
		value[strlen(value) - 1] = '\0';

		if (strcmp(option, "SESSION_DB") == 0)
			c->session_db = strdup(value);
		else if (strcmp(option, "APP_HOST") == 0)
			c->app_host = strdup(value);
		else if (strcmp(option, "WWW_HOST") == 0)
			c->www_host = strdup(value);
		else if (strcmp(option, "PRIMARY_NS") == 0)
			c->primary_ns = strdup(value);
		else if (strcmp(option, "SECONDARY_NS") == 0)
			c->secondary_ns = strdup(value);
		else if (strcmp(option, "PRIMARY_NS_IP") == 0)
			c->primary_ns_ip = strdup(value);
		else if (strcmp(option, "DB_USER") == 0)
			c->db_user = strdup(value);
		else if (strcmp(option, "DB_PASS") == 0)
			c->db_pass = strdup(value);
		else if (strcmp(option, "DB_NAME") == 0)
			c->db_name = strdup(value);
		else if (strcmp(option, "DB_HOST") == 0)
			c->db_host = strdup(value);
		else if (strcmp(option, "DB_SHOST") == 0)
			c->db_shost = strdup(value);
		else if (strcmp(option, "DB_SOCKET_NAME") == 0)
			c->db_socket_name = strdup(value);
		else if (strcmp(option, "DB_PORT_NUM") == 0)
			c->db_port_num = atoi(value);
		else if (strcmp(option, "DB_FLAGS") == 0)
			c->db_flags = atoi(value);
		else if (strcmp(option, "MAIL_CMD") == 0)
			c->mail_cmd = strdup(value);
		else if (strcmp(option, "MAIL_FROM") == 0)
			c->mail_from = strdup(value);
		else if (strcmp(option, "LOG_DIR") == 0)
			c->log_dir = strdup(value);
		else if (strcmp(option, "NR_PROCS") == 0)
			c->nr_procs = atoi(value);
		else if (strcmp(option, "DEBUG_LEVEL") == 0)
			c->debug_level = atoi(value);
		else if (strcmp(option, "MULTI_TENANT") == 0)
			c->multi_tenant = atoi(value);
		else if (strcmp(option, "PAYPAL_BID") == 0)
			c->paypal_bid = strdup(value);
		else if (strcmp(option, "PAYPAL_REC_EMAIL") == 0)
			c->paypal_rec_email = strdup(value);
		else if (strcmp(option, "PAYPAL_HOST") == 0)
			c->paypal_host = strdup(value);
	}

	fclose(fp);
	set_defaults(c);

	return c;
}
