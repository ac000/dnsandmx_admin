/*
 * dax_config.h
 *
 * Copyright (C) 	2012	OpenTech Labs
 *				Andrew Clayton <andrew@digital-domain.net>
 *			2013	DNSandMX
 *				Andrew Clayton <andrew@dnsandmx.com>
 *
 * Licensed under the GNU Affero General Public License version 3
 * See AGPL-3.0.txt
 */

#ifndef _DAX_CONFIG_H_
#define _DAX_CONFIG_H_

char *rec_session_db;

/* Default log path set in src/dax.c */
extern char *log_dir;

char *mail_cmd;
char *mail_from;

char *app_host;
char *www_host;

char *primary_ns;
char *secondary_ns;
char *primary_ns_ip;

char *db_user;
char *db_password;
char *db_name;
char *db_host;
char *db_shost;
/* These have default values set in src/db.c */
extern char *db_socket_name;
extern unsigned int db_port_num;
extern unsigned int db_flags;

char *paypal_bid;	/* PayPal Business ID */
char *paypal_rec_email;	/* PayPal receiver email address */
char *paypal_host;	/* Where we send the user for payment */

int nr_procs;

int multi_tenant;

extern int debug_level;	/* Default debug level set in src/dax.c */

#define SESSION_DB	rec_session_db

#define LOG_DIR		log_dir
#define ACCESS_LOG	access_log_path
#define ERROR_LOG	error_log_path
#define SQL_LOG		sql_log_path
#define DEBUG_LOG	debug_log_path

#define MAIL_CMD	mail_cmd
#define MAIL_FROM	mail_from

#define APP_HOST	app_host
#define WWW_HOST	www_host

#define PRIMARY_NS	primary_ns
#define SECONDARY_NS	secondary_ns
#define PRIMARY_NS_IP	primary_ns_ip

#define DB_USER		db_user
#define DB_PASS		db_password
#define DB_NAME		db_name
#define DB_HOST		db_host
#define DB_SHOST	db_shost
#define DB_SOCKET_NAME	db_socket_name
#define DB_PORT_NUM	db_port_num
#define DB_FLAGS	db_flags

#define PAYPAL_BID		paypal_bid
#define PAYPAL_REC_EMAIL	paypal_rec_email
#define PAYPAL_HOST		paypal_host

#define NR_PROCS	nr_procs

#define MULTI_TENANT	multi_tenant

#define DEBUG_LEVEL	debug_level

#endif /* _DAX_CONFIG_H_ */
