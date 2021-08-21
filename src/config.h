/*
 * config.h
 *
 * Copyright (C) 	2012	OpenTech Labs
 *				Andrew Clayton <andrew@digital-domain.net>
 *			2013	DNSandMX
 *				Andrew Clayton <andrew@dnsandmx.com>
 *
 * Licensed under the GNU Affero General Public License version 3
 * See AGPL-3.0.txt
 */

#ifndef _CONFIG_H_
#define _CONFIG_H_

struct cfg {
	const char *session_db;

	const char *log_dir;

	const char *mail_cmd;
	const char *mail_from;

	const char *app_host;
	const char *www_host;

	const char *primary_ns;
	const char *secondary_ns;
	const char *primary_ns_ip;

	const char *db_user;
	const char *db_pass;
	const char *db_name;
	const char *db_host;
	const char *db_shost;
	const char *db_socket_name;
	unsigned int db_port_num;
	unsigned int db_flags;

	const char *paypal_bid;		/* PayPal Business ID */
	const char *paypal_rec_email;	/* PayPal receiver email address */
	const char *paypal_host;	/* Where we send the user for payment */

	int nr_procs;

	int multi_tenant;

	int debug_level;	/* Default debug level set in src/dax.c */
};

#define CFG_DEF_LOG_DIR			"/tmp"
#define CFG_DEF_DB_HOST			"localhost"
#define CFG_DEF_DB_PORT_NUM		3306

extern const struct cfg *get_config(const char *filename);

#endif /* _CONFIG_H_ */
