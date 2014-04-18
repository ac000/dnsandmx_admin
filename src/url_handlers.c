/*
 * url_handlers.c
 *
 * Copyright (C) 2012 - 2013	OpenTech Labs
 *				Andrew Clayton <andrew@digital-domain.net>
 *		 2013 - 2014	DNSandMX
 *				Andrew Clayton <andrew@dnsandmx.com>
 *
 * Licensed under the GNU Affero General Public License version 3
 * See AGPL-3.0.txt
 */

#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <alloca.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdbool.h>
#include <setjmp.h>

#include <mhash.h>

#include <glib.h>

/* HTML template library */
#include <ctemplate.h>

#include <curl/curl.h>

#include "common.h"
#include "utils.h"
#include "tools.h"
#include "audit.h"
#include "csrf.h"

struct dom_rec_ent {
	const char *domain;
	const char *name;
	const char *type;
	const char *content;
	int prio;
	int ttl;
};

/*
 * /login/
 *
 * HTML is in templates/login.tmpl
 *
 * Display the login screen.
 */
static void login(void)
{
	int ret = 1;
	TMPL_varlist *vl = NULL;
	TMPL_fmtlist *fmtlist = NULL;

	if (qvars) {
		ret = check_auth();
		if (ret == 0) {
			unsigned long long sid = log_login();

			create_session(sid);
			fcgx_p("Location: /overview/\r\n\r\n");
			return; /* Successful login */
		}
	}

	if (ret == -1)
		vl = add_html_var(vl, "logged_in", "no");
	if (ret == -2)
		vl = add_html_var(vl, "enabled", "no");
	if (ret == -3)
		vl = add_html_var(vl, "ipacl", env_vars.remote_addr);
	vl = add_html_var(vl, "www_host", WWW_HOST);

	fmtlist = TMPL_add_fmt(fmtlist, "de_xss", de_xss);
	send_template("templates/login.tmpl", vl, fmtlist);
	TMPL_free_varlist(vl);
	TMPL_free_fmtlist(fmtlist);
}

/*
 * /logout/
 *
 * HTML is in templates/logout.tmpl
 *
 * Clean up a users session. Remove their entry from the sessions db and
 * set the session_id browser cookie to expired.
 */
static void logout(void)
{
	TCTDB *tdb;
	TDBQRY *qry;
	TCLIST *res;
	int rsize;
	const char *rbuf;
	TMPL_varlist *vl = NULL;
	TMPL_fmtlist *fmtlist = NULL;

	tdb = tctdbnew();
	tctdbopen(tdb, SESSION_DB, TDBOWRITER);

	qry = tctdbqrynew(tdb);
	tctdbqryaddcond(qry, "session_id", TDBQCSTREQ,
					user_session.session_id);
	res = tctdbqrysearch(qry);
	rbuf = tclistval(res, 0, &rsize);
	tctdbout(tdb, rbuf, strlen(rbuf));

	tclistdel(res);
	tctdbqrydel(qry);

	tctdbclose(tdb);
	tctdbdel(tdb);

	/* Immediately expire the session cookies */
	fcgx_p("Set-Cookie: session_id=deleted; "
				"expires=Thu, 01 Jan 1970 00:00:01 GMT; "
				"path=/; httponly\r\n");

	vl = add_html_var(vl, "www_host", WWW_HOST);

        fmtlist = TMPL_add_fmt(fmtlist, "de_xss", de_xss);
	send_template("templates/logout.tmpl", vl, fmtlist);
        TMPL_free_varlist(vl);
        TMPL_free_fmtlist(fmtlist);
}

/*
 * Helper function to add/update a DNS record.
 */
static void __dns_record_to_db(struct dom_rec_ent *dre, int domain_id,
			       int record_id)
{
	char host[FQDN_MAX + 1];
	const char *sql_fmt;

	make_fqdn(dre->name, dre->domain, host, FQDN_MAX + 1);

	if (IS_SET(qvar("update"))) {
		sql_fmt = "REPLACE INTO pdns.records (id, domain_id, name, "
			"type, content, ttl, prio, change_date) VALUES "
			"(%d, %d, '%s', '%s', '%s', %d, %d, %d)";
		sql_query(conn, sql_fmt, record_id, domain_id, host, dre->type,
				dre->content, dre->ttl, dre->prio, time(NULL));
	} else {
		sql_fmt = "INSERT INTO pdns.records (domain_id, name, type, "
			"content, ttl, prio, change_date) VALUES "
			"(%d, '%s', '%s', '%s', %d, %d, %d)";
		sql_query(conn, sql_fmt, domain_id, host, dre->type,
				dre->content, dre->ttl, dre->prio, time(NULL));
	}
}

/*
 * Helper function to update a users settings. This is called from settings()
 */
static void __update_user_settings(void)
{
	TCTDB *tdb;
	TDBQRY *qry;
	TCLIST *res;
	TCMAP *cols;
	int rsize;
	int primary_key_size;
	int ipacl = 0;
	const char *rbuf;
	const char *hash;
	char pkbuf[256];
	char login_at[21];
	char last_seen[21];
	char uid[11];
	char sid[21];
	char restrict_ip[2];
	char capabilities[4];
	char *username;
	char *name;
	char *acl;

	if (IS_SET(qvar("dax_pass1"))) {
		hash = generate_password_hash(SHA512, qvar("dax_pass1"));
	} else {
		MYSQL_RES *res;
		MYSQL_ROW row;

		res = sql_query(conn, "SELECT password FROM passwd WHERE "
				"uid = %u", user_session.uid);
		row = mysql_fetch_row(res);
		hash = row[0];
		mysql_free_result(res);
	}

	username = make_mysql_safe_string(qvar("dax_email1"));
	name = make_mysql_safe_string(qvar("dax_name"));
	sql_query(conn, "UPDATE passwd SET username = '%s', password = '%s', "
			"name = '%s' WHERE uid = %u",
			username, hash, name, user_session.uid);

	if (IS_SET(qvar("dax_ipacl_act")))
		ipacl = 1;
	acl = make_mysql_safe_string(qvar("dax_ipacl"));
	/*
	 * We store the ACL as space separated values but they are
	 * displayed and entered one per line
	 */
	sql_query(conn, "REPLACE INTO ipacl (uid, enabled, list) VALUES "
			"(%u, %d, REPLACE('%s', '\r\n', ' '))",
			user_session.uid, ipacl, acl);

	/*
	 * We want to update the users session.entry. This entails removing
	 * the old session first then storing the updated session.
	 */
	tdb = tctdbnew();
	tctdbopen(tdb, SESSION_DB, TDBOREADER | TDBOWRITER);

	snprintf(uid, sizeof(uid), "%u", user_session.uid);
	qry = tctdbqrynew(tdb);
	tctdbqryaddcond(qry, "uid", TDBQCNUMEQ, uid);
	res = tctdbqrysearch(qry);
	rbuf = tclistval(res, 0, &rsize);
	tctdbout(tdb, rbuf, strlen(rbuf));

	tclistdel(res);
	tctdbqrydel(qry);

	primary_key_size = sprintf(pkbuf, "%ld", (long)tctdbgenuid(tdb));
	snprintf(sid, sizeof(sid), "%llu", user_session.sid);
	snprintf(login_at, sizeof(login_at), "%ld", user_session.login_at);
	snprintf(last_seen, sizeof(last_seen), "%ld", time(NULL));
	snprintf(restrict_ip, sizeof(restrict_ip), "%d",
			user_session.restrict_ip);
	snprintf(capabilities, sizeof(capabilities), "%d",
			user_session.capabilities);
	name = realloc(name, strlen(qvar("dax_name")) + 1);
	sprintf(name, "%s", qvar("dax_name"));
	username = realloc(username, strlen(qvar("dax_email1")) + 1);
	sprintf(username, "%s", qvar("dax_email1"));
	cols = tcmapnew3("tenant", user_session.tenant,
			"sid", sid,
			"uid", uid,
			"username", username,
			"name", name,
			"login_at", login_at,
			"last_seen", last_seen,
			"origin_ip", user_session.origin_ip,
			"client_id", user_session.client_id,
			"session_id", user_session.session_id,
			"csrf_token", user_session.csrf_token,
			"restrict_ip", restrict_ip,
			"capabilities", capabilities,
			NULL);
	tctdbput(tdb, pkbuf, primary_key_size, cols);

	tcmapdel(cols);

	tctdbclose(tdb);
	tctdbdel(tdb);
	free(username);
	free(name);
	free(acl);
}

/*
 * /settings/
 *
 * HTML is in templates/settings.tmpl
 *
 * Allow users to change their details.
 */
static void settings(void)
{
	bool form_err = false;
	TMPL_varlist *vl = NULL;
	TMPL_fmtlist *fmtlist = NULL;

	/*
	 * If we got POST data, update the users settings before
	 * showing them.
	 */
	if (IS_POST() && valid_csrf_token()) {
		const char *email1 = qvar("dax_email1");
		const char *email2 = qvar("dax_email2");

		if (!is_valid_email_address(email1) &&
		    !is_valid_email_address(email2)) {
			vl = add_html_var(vl, "valid_email", "no");
			form_err = true;
		} else if (strcmp(email1, email2) != 0) {
			vl = add_html_var(vl, "emails_match", "no");
			form_err = true;
		} else if (strcmp(user_session.username, email1) != 0) {
			if (user_already_exists(email1)) {
				vl = add_html_var(vl, "user_exists", "yes");
				form_err = true;
			}
		}
		if (form_err)
			vl = add_html_var(vl, "email_error", "yes");

		if (strlen(qvar("dax_pass1")) > 7 &&
		    strlen(qvar("dax_pass2")) > 7) {
			if (strcmp(qvar("dax_pass1"), qvar("dax_pass2")) != 0) {
				vl = add_html_var(vl, "pass_error", "mismatch");
				form_err = true;
			}
		/*
		 * If the password fields are > 0 in length, then we tried
		 * to update it.
		 */
		} else if (IS_SET(qvar("dax_pass1")) ||
			   IS_SET(qvar("dax_pass2"))) {
			vl = add_html_var(vl, "pass_error", "length");
			form_err = true;
		}

		if (!form_err) {
			__update_user_settings();
			/* After the update we want to re-GET */
			fcgx_p("Location: /settings/?updated=yes\r\n\r\n");
			return;
		}
	} else {
		if (IS_SET(qvar("updated")))
			vl = add_html_var(vl, "updated", "yes");
	}

	/*
	 * If form_err is still false, then either we got a GET and just want
	 * to show the users settings from the database. Or we got a POST
	 * and successfully updated the users settings and want to show them.
	 *
	 * Else we tried to update the users settings but made some mistake
	 * and need to re-edit them in which case we need show the values
	 * from the POST'd form.
	 */
	if (!form_err) {
		MYSQL_RES *res;
		GHashTable *db_row = NULL;

		res = sql_query(conn, "SELECT username, name, ipacl.enabled, "
				"REPLACE(ipacl.list, ' ', '\r\n') AS list "
				"FROM passwd, ipacl WHERE passwd.uid = %u AND "
				"ipacl.uid = passwd.uid", user_session.uid);
		db_row = get_dbrow(res);

		vl = add_html_var(vl, "username", get_var(db_row, "username"));
		vl = add_html_var(vl, "dax_email1", get_var(db_row,
					"username"));
		vl = add_html_var(vl, "dax_email2", get_var(db_row,
					"username"));
		vl = add_html_var(vl, "dax_name", get_var(db_row, "name"));
		vl = add_html_var(vl, "dax_ipacl", get_var(db_row, "list"));
		vl = add_html_var(vl, "dax_ipacl_act", get_var(db_row,
					"enabled"));

		free_vars(db_row);
		mysql_free_result(res);
	} else {
		vl = add_html_var(vl, "username", qvar("dax_email1"));
		vl = add_html_var(vl, "dax_email1", qvar("dax_email1"));
		vl = add_html_var(vl, "dax_email2", qvar("dax_email2"));
		vl = add_html_var(vl, "dax_name", qvar("dax_name"));
		vl = add_html_var(vl, "dax_ipacl", qvar("dax_ipacl"));
		vl = add_html_var(vl, "dax_ipacl_act", qvar("dax_ipacl_act"));
	}

	vl = add_csrf_token(vl);
	fmtlist = TMPL_add_fmt(fmtlist, "de_xss", de_xss);
	send_template("templates/settings.tmpl", vl, fmtlist);
	TMPL_free_varlist(vl);
	TMPL_free_fmtlist(fmtlist);
}

/*
 * /add_mail_domain/
 *
 * HTML is in templates/add_mail_domain.tmpl
 */
static void add_mail_domain(void)
{
	char *domain = NULL;
	const char *m_type;
	bool form_err = false;
	TMPL_varlist *vl = NULL;
	TMPL_fmtlist *fmtlist = NULL;

	if (IS_POST() && valid_csrf_token()) {
		MYSQL_RES *res;
		MYSQL *mconn;
		unsigned long long id;

		m_type = qvar("mail_type");

		domain = make_mysql_safe_string(qvar("dax_domain"));
		if (!is_valid_hostname(domain)) {
			form_err = true;
			vl = add_html_var(vl, "domain_error", "true");
		}
		dotchomp(domain);
		res = sql_query(conn, "SELECT domain FROM mail_domains WHERE "
				"domain = '%s'", domain);
		if (mysql_num_rows(res) > 0) {
			form_err = true;
			vl = add_html_var(vl, "domain_error", "true");
			vl = add_html_var(vl, "domain_exists", "true");
		}
		mysql_free_result(res);

		if (!form_err) {
			sql_query(conn, "INSERT INTO mail_domains (uid, "
					"domain, type, added, expires) VALUES "
					"(%u, '%s', '%s', %ld, %ld)",
					user_session.uid, domain, m_type,
					time(NULL), time(NULL) + 86400 * 30);
			id = mysql_insert_id(conn);
		}

		if (!form_err && strcmp(m_type, "MX") == 0) {
			/* Backup MX */
			mconn = db_conn(db_shost, "postfix", true);
			sql_query(mconn, "INSERT INTO postfix.relay_domains "
					"(domain_id, domain) VALUES (%llu, "
					"'%s')", id, domain);
			mysql_close(mconn);
		} else if (!form_err) {
			/* MAil forwarding */
			const char *ld_sql = "INSERT INTO "
				"postfix.local_domains (domain_id, domain) "
				"VALUES (%llu, '%s')";
			const char *fwd_sql = "INSERT INTO postfix.forwarding "
				"(domain_id, source, destination) "
				"VALUES (%llu, '%s@%s', '%s')";

			sql_query(conn, ld_sql, id, domain);

			sql_query(conn, fwd_sql, id, "root", domain,
					user_session.username);
			sql_query(conn, fwd_sql, id, "abuse", domain,
					user_session.username);
			sql_query(conn, fwd_sql, id, "hostmaster", domain,
					user_session.username);
			sql_query(conn, fwd_sql, id, "postmaster", domain,
					user_session.username);
			sql_query(conn, fwd_sql, id, "MAILER-DAEMON", domain,
					user_session.username);

			mconn = db_conn(db_shost, "postfix", true);
			sql_query(mconn, ld_sql, id, domain);

			sql_query(mconn, fwd_sql, id, "root", domain,
					user_session.username);
			sql_query(mconn, fwd_sql, id, "abuse", domain,
					user_session.username);
			sql_query(mconn, fwd_sql, id, "hostmaster", domain,
					user_session.username);
			sql_query(mconn, fwd_sql, id, "postmaster", domain,
					user_session.username);
			sql_query(mconn, fwd_sql, id, "MAILER-DAEMON", domain,
					user_session.username);
			mysql_close(mconn);
		}

		if (!form_err) {
			fcgx_p("Location: /overview/\r\n\r\n");
			goto out;
		}
	}

	/* GET or unsuccessful POST */
	if (!form_err) {
		/* GET */
		/* Set some default values for the form */
		vl = add_html_var(vl, "mail_type", "MX");
	} else {
		/* POST with form errors */
		vl = add_html_var(vl, "dax_domain", qvar("dax_domain"));
		vl = add_html_var(vl, "dax_email", qvar("dax_email"));
		vl = add_html_var(vl, "mail_type", qvar("mail_type"));
		vl = add_html_var(vl, "dax_master", qvar("dax_master"));
	}

	vl = add_csrf_token(vl);
        fmtlist = TMPL_add_fmt(fmtlist, "de_xss", de_xss);
	send_template("templates/add_mail_domain.tmpl", vl, fmtlist);
        TMPL_free_fmtlist(fmtlist);
out:
	TMPL_free_varlist(vl);
	free(domain);
}

/*
 * /delete_mail_domain/
 *
 * HTML is in templates/delete_mail_domain.tmpl
 */
static void delete_mail_domain(void)
{
	int domain_id;
	const char *domain;
	char *type;
	MYSQL_RES *res;
	TMPL_varlist *vl = NULL;
	TMPL_fmtlist *fmtlist = NULL;
	GHashTable *db_row = NULL;

	domain_id = atoi(qvar("domain_id"));
	if (!is_users_domain(domain_id, "mail_domains"))
		goto out;

	res = sql_query(conn, "SELECT domain, type FROM mail_domains WHERE "
				"domain_id = %d", domain_id);
	db_row = get_dbrow(res);
	type = strdupa(get_var(db_row, "type"));
	domain = get_var(db_row, "domain");
	vl = add_html_var(vl, "domain", domain);
	vl = add_html_var(vl, "domain_id", qvar("domain_id"));
	vl = add_html_var(vl, "username", user_session.username);
	free_vars(db_row);
	mysql_free_result(res);

	if (IS_POST() && valid_csrf_token()) {
		int ret;

		ret = check_auth();
		if (ret == 0) {
			MYSQL *mconn;

			if (strcmp(type, "MX") == 0) {
				mconn = db_conn(db_shost, "postfix", true);
				sql_query(mconn, "DELETE FROM "
						"postfix.relay_domains WHERE "
						"domain_id = %d", domain_id);
				mysql_close(mconn);
			} else {
				sql_query(conn, "DELETE FROM "
						"postfix.local_domains WHERE "
						"domain_id = %d", domain_id);
				mconn = db_conn(db_shost, "postfix", true);
				sql_query(mconn, "DELETE FROM "
						"postfix.local_domains WHERE "
						"domain_id = %d", domain_id);
				mysql_close(mconn);
			}

			sql_query(conn, "DELETE FROM mail_domains WHERE "
					"domain_id = %d", domain_id);

			fcgx_p("Location: /overview/\r\n\r\n");
			goto out2;
		} else {
			vl = add_html_var(vl, "auth_err", "yes");
		}
	}

out:
	add_csrf_token(vl);
	fmtlist = TMPL_add_fmt(fmtlist, "de_xss", de_xss);
	send_template("templates/delete_mail_domain.tmpl", vl, fmtlist);
out2:
	TMPL_free_varlist(vl);
	TMPL_free_fmtlist(fmtlist);
}

/*
 * /delete_mail_fwd_record/
 */
static void delete_mail_fwd_record(void)
{
	int domain_id = atoi(qvar("domain_id"));
	int record_id = atoi(qvar("record_id"));
	MYSQL *mconn;
	const char *d_sql = "DELETE FROM postfix.forwarding WHERE "
		"domain_id = %d AND id = %d";

	if (!valid_csrf_token())
		goto out;

	if (!is_users_domain(domain_id, "mail_domains"))
		goto out;

	sql_query(conn, d_sql, domain_id, record_id);

	mconn = db_conn(db_shost, "postfix", true);
	sql_query(mconn, d_sql, domain_id, record_id);
	mysql_close(mconn);

out:
	fcgx_p("Location: /mail_forwarding/?domain_id=%d\r\n\r\n", domain_id);
}

/*
 * /issue_etrn/
 */
static void issue_etrn(void)
{
	int domain_id;
	int sockfd;
	int len;
	const char *domain;
	struct addrinfo hints;
	struct addrinfo *res;
	ssize_t bytes_read;
	char buf[BUF_SIZE];
	bool err = true;

	domain_id = atoi(qvar("domain_id"));

	if (!valid_csrf_token())
		goto out2;

	if (!is_users_domain(domain_id, "mail_domains"))
		goto out2;

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

	getaddrinfo(db_shost, "25", &hints, &res);
	sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	connect(sockfd, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);

	/* Get banner */
	bytes_read = read(sockfd, buf, BUF_SIZE);
	buf[bytes_read - 2] = '\0';
	if (!strstr(buf, "ESMTP")) {
		d_fprintf(error_log, "Unable to connect to %s:25\n", db_shost);
		goto out;
	}

	/* Send HELO */
	len = snprintf(buf, sizeof(buf), "HELO %s\r\n", db_host);
	write(sockfd, buf, len);
	bytes_read = read(sockfd, buf, BUF_SIZE);
	buf[bytes_read - 2] = '\0';

	domain = qvar("domain");

	/* Issue ETRN */
	len = snprintf(buf, sizeof(buf), "ETRN %s\r\n", domain);
	write(sockfd, buf, len);
	bytes_read = read(sockfd, buf, BUF_SIZE);
	buf[bytes_read - 2] = '\0';
	if (!strstr(buf, "250 ")) {
		d_fprintf(error_log, "Error issuing ETRN for %s\n", domain);
		goto out;
	}

	write(sockfd, "QUIT\r\n", 6);
	err = false;

out:
	close(sockfd);
out2:
	fcgx_p("Location: /backup_mx/?domain_id=%d&etrn=%d\r\n\r\n",
		domain_id, err);
}

/*
 * Helper function called by add_domain()
 */
static void __add_default_dns_records(unsigned long long id,
				     const char *domain,
				     const char *hostmaster, bool reverse)
{
	const char *rdb = "pdns.records";
	const char *rfields = "domain_id, name, type, content, ttl, "
		"change_date";
	time_t chtime = time(NULL);

	/* SOA Record */
	sql_query(conn, "INSERT INTO %s (%s) VALUES "
			"(%llu, '%s', 'SOA', '%s %s 0 10800 3600 604800 900', "
			"3600, %d)",
			rdb, rfields, id, domain, PRIMARY_NS, hostmaster,
			chtime);

	/* NS Record */
	sql_query(conn, "INSERT INTO %s (%s) VALUES "
			"(%llu, '%s', 'NS', '%s', 3600, %d)",
			rdb, rfields, id, domain, PRIMARY_NS, chtime);

	/* NS Record */
	sql_query(conn, "INSERT INTO %s (%s) VALUES "
			"(%llu, '%s', 'NS', '%s', 3600, %d)",
			rdb, rfields, id, domain, SECONDARY_NS, chtime);

	if (reverse)
		return;

	/* localhost A Record */
	sql_query(conn, "INSERT INTO %s (%s) VALUES "
			"(%llu, 'localhost.%s', 'A', '127.0.0.1', 86400, %d)",
			rdb, rfields, id, domain, chtime);

	/* localhost AAAA Record */
	sql_query(conn, "INSERT INTO %s (%s) VALUES "
			"(%llu, 'localhost.%s', 'AAAA', '::1', 86400, %d)",
			rdb, rfields, id, domain, chtime);
}

/*
 * /add_dns_domain/
 *
 * HTML is in templates/add_dns_domain.tmpl
 */
static void add_dns_domain(void)
{
	char *domain = NULL;
	char *hostmaster = NULL;
	const char *s_type;
	bool form_err = false;
	TMPL_varlist *vl = NULL;
	TMPL_fmtlist *fmtlist = NULL;

	if (IS_POST() && valid_csrf_token()) {
		char *htmp;
		const char *master;
		const char *domain_sql_fmt;
		MYSQL_RES *res;

		domain = make_mysql_safe_string(qvar("dax_domain"));
		if (strcmp(qvar("server_type"), "primary") == 0)
			s_type = "MASTER";
		else
			s_type = "SLAVE";

		if (!is_valid_hostname(domain)) {
			form_err = true;
			vl = add_html_var(vl, "domain_error", "true");
		}
		dotchomp(domain);
		res = sql_query(conn, "SELECT name FROM pdns.domains WHERE "
			"pdns.domains.name = '%s'", domain);
		if (mysql_num_rows(res)) {
			form_err = true;
			vl = add_html_var(vl, "domain_error", "true");
			vl = add_html_var(vl, "domain_exists", "true");
		}
		mysql_free_result(res);

		/* Hostmaster address should be entered with a '@' */
		if (!IS_SET(qvar("dax_hostmaster")) ||
		    !strstr(qvar("dax_hostmaster"), "@")) {
			form_err = true;
			vl = add_html_var(vl, "hostmaster_error", "true");
		}
		htmp = alloca(strlen(qvar("dax_hostmaster")) * 2 + 1);
		email_to_hostmaster(qvar("dax_hostmaster"), htmp);
		hostmaster = make_mysql_safe_string(htmp);
		dotchomp(hostmaster);

		/*
		 * If we are to be a slave for this domain, we need the
		 * master name servers IP address.
		 *
		 * The crazy domain_sql_fmt thing is just so we can get A
		 * NULL into the database for when there is no MASTER.
		 *
		 * NULL doesn't go into the databases quoted but an IP
		 * address does.
		 */
		if (strcmp(s_type, "SLAVE") == 0) {
			if (!IS_SET(qvar("dax_master")) ||
			    (!is_valid_ipv4_addr(qvar("dax_master")) &&
			     !is_valid_ipv6_addr(qvar("dax_master")))) {
				form_err = true;
				vl = add_html_var(vl, "master_error", "true");
			} else {
				domain_sql_fmt =
					"INSERT INTO pdns.domains "
					"(name, master, type) VALUES "
					"('%s', '%s', '%s')";
				master = qvar("dax_master");
			}
		} else {
			domain_sql_fmt =
				"INSERT INTO pdns.domains "
				"(name, master, type) VALUES "
				"('%s', %s, '%s')";
			master = NULL;
		}

		if (!form_err) {
			MYSQL *sconn;
			bool reverse;
			unsigned long long id;

			sql_query(conn, domain_sql_fmt, domain,
					!master ? "NULL" : master, s_type);
			id = mysql_insert_id(conn);

			/* Add domain entry on slave server */
			sconn = db_conn(db_shost, "pdns", true);
			sql_query(sconn, "INSERT INTO pdns.domains (name, "
					"master, type) VALUES "
					"('%s', '%s', 'SLAVE')",
					domain, master ? master :
					PRIMARY_NS_IP);
			mysql_close(sconn);

			sql_query(conn, "INSERT INTO domains (uid, domain_id, "
					"added, expires) VALUES (%u, %llu, "
					"%ld, %ld)", user_session.uid, id,
					time(NULL), time(NULL) + 86400 * 30);

			reverse = is_reverse_zone(domain);
			if (strcmp(s_type, "MASTER") == 0)
				__add_default_dns_records(id, domain,
						hostmaster, reverse);

			fcgx_p("Location: /overview/\r\n\r\n");
			goto out;
		}
	}

	/* GET or unsuccessful POST */
	if (!form_err) {
		/* GET */
		/* Set some default values for the form */
		vl = add_html_var(vl, "dax_hostmaster", user_session.username);
		vl = add_html_var(vl, "server_type", "MASTER");
	} else {
		/* POST with form errors */
		vl = add_html_var(vl, "dax_domain", qvar("dax_domain"));
		vl = add_html_var(vl, "dax_hostmaster", qvar("dax_hostmaster"));
		vl = add_html_var(vl, "server_type", s_type);
		vl = add_html_var(vl, "dox_master", qvar("dax_master"));
	}

	vl = add_csrf_token(vl);
	fmtlist = TMPL_add_fmt(fmtlist, "de_xss", de_xss);
	send_template("templates/add_dns_domain.tmpl", vl, fmtlist);
	TMPL_free_fmtlist(fmtlist);
out:
	TMPL_free_varlist(vl);
	free(domain);
	free(hostmaster);
}

/*
 * /delete_dns_domain/
 *
 * HTML is in templates/delete_dns_domain.tmpl
 */
static void delete_dns_domain(void)
{
	int domain_id;
	char *domain;
	MYSQL_RES *res;
	TMPL_varlist *vl = NULL;
	TMPL_fmtlist *fmtlist = NULL;
	GHashTable *db_row = NULL;

	domain_id = atoi(qvar("domain_id"));
	if (!is_users_domain(domain_id, "domains"))
		goto out;

	res = sql_query(conn, "SELECT pdns.domains.name AS domain FROM "
			"pdns.domains WHERE pdns.domains.id = %d",
			domain_id);
	db_row = get_dbrow(res);
	domain = strdupa(get_var(db_row, "domain"));
	vl = add_html_var(vl, "domain", domain);
	vl = add_html_var(vl, "domain_id", qvar("domain_id"));
	vl = add_html_var(vl, "username", user_session.username);
	free_vars(db_row);
	mysql_free_result(res);

	if (IS_POST() && valid_csrf_token()) {
		int ret;

		ret = check_auth();
		if (ret == 0) {
			MYSQL *sconn;
			char *sdom = make_mysql_safe_string(domain);

			sql_query(conn, "DELETE FROM pdns.domains WHERE "
					"pdns.domains.id = %d", domain_id);
			sql_query(conn, "DELETE FROM domains WHERE domain_id "
					"= %d", domain_id);

			/* Delete from slave server */
			sconn = db_conn(db_shost, "pdns", true);
			sql_query(sconn, "DELETE FROM pdns.domains WHERE "
                                        "pdns.domains.name = '%s'", sdom);
			mysql_close(sconn);
			free(sdom);

			fcgx_p("Location: /overview/\r\n\r\n");
			goto out2;
		} else {
			vl = add_html_var(vl, "auth_err", "yes");
		}
	}

out:
	add_csrf_token(vl);
	fmtlist = TMPL_add_fmt(fmtlist, "de_xss", de_xss);
	send_template("templates/delete_dns_domain.tmpl", vl, fmtlist);
out2:
	TMPL_free_varlist(vl);
	TMPL_free_fmtlist(fmtlist);
}

/*
 * /delete_dns_record/
 */
static void delete_dns_record(void)
{
	int domain_id;
	int record_id;

	domain_id = atoi(qvar("domain_id"));

	if (!valid_csrf_token())
		goto out;

	if (!is_users_domain(domain_id, "domains"))
		goto out;

	record_id = atoi(qvar("record_id"));
	sql_query(conn, "DELETE FROM pdns.records WHERE "
			"pdns.records.domain_id = %d AND pdns.records.id = %d",
			domain_id, record_id);
	/*
	 * When deleting a record, we need to make sure the serial gets
	 * changed. As we are using the change_date field to determine
	 * the serial, update the SOA's change_date field.
	 */
	sql_query(conn, "UPDATE pdns.records SET change_date = %d WHERE "
			"pdns.records.domain_id = %d AND pdns.records.type = "
			"'SOA'", time(NULL), domain_id);
out:
	fcgx_p("Location: /records/?domain_id=%d&type=%s\r\n\r\n",
			domain_id, qvar("type"));
}

/*
 * /soa_record/
 *
 * HTML is in templates/soa_record.tmpl
 */
static void soa_record(void)
{
	int domain_id;
	int record_id = 0;
	int refresh;
	int retry;
	int expire;
	int ncttl;
	int ttl;
	char *pns = NULL;
	char *hostmaster = NULL;
	char *domain = NULL;
	bool form_err = false;
	MYSQL_RES *res;
	TMPL_varlist *vl = NULL;
	TMPL_fmtlist *fmtlist = NULL;
	GHashTable *db_row = NULL;

	domain_id = atoi(qvar("domain_id"));
	if (!is_domain_editable(domain_id, "domains"))
		goto out;

	vl = add_html_var(vl, "domain_id", qvar("domain_id"));

	if (IS_SET(qvar("record_id"))) {
		record_id = atoi(qvar("record_id"));
		vl = add_html_var(vl, "record_id", qvar("record_id"));
	}

	if (IS_POST() && valid_csrf_token()) {
		char *htmp;

		refresh = atoi(qvar("dax_refresh"));
		retry = atoi(qvar("dax_retry"));
		expire = atoi(qvar("dax_expire"));
		ncttl = atoi(qvar("dax_ncttl"));
		ttl = atoi(qvar("dax_ttl"));
		pns = make_mysql_safe_string(qvar("dax_pns"));
		domain = make_mysql_safe_string(qvar("domain"));

		if (refresh < 60) {
			form_err = true;
			vl = add_html_var(vl, "refresh_error", "yes");
		}
		if (retry < 60) {
			form_err = true;
			vl = add_html_var(vl, "retry_error", "yes");
		}
		if (expire < 60) {
			form_err = true;
			vl = add_html_var(vl, "expire_error", "yes");
		}
		if (ncttl < 60) {
			form_err = true;
			vl = add_html_var(vl, "ncttl_error", "yes");
		}
		if (ttl < 60) {
			form_err = true;
			vl = add_html_var(vl, "ttl_error", "yes");
		}

		/* Hostmaster address should be entered with an '@' */
		if (!IS_SET(qvar("dax_hostmaster")) ||
		    !strstr(qvar("dax_hostmaster"), "@")) {
			form_err = true;
			vl = add_html_var(vl, "hostmaster_error", "true");
		}
		htmp = alloca(strlen(qvar("dax_hostmaster")) * 2 + 1);
		email_to_hostmaster(qvar("dax_hostmaster"), htmp);
		hostmaster = make_mysql_safe_string(htmp);
		dotchomp(hostmaster);

		if (!is_valid_hostname(pns)) {
			form_err = true;
			vl = add_html_var(vl, "hostname_error", "yes");
		}

		if (!form_err) {
			const char *db = "pdns.records";
			const char *fields =
				"domain_id, name, type, content, ttl, "
				"change_date";
			const char *type = "SOA";

			sql_query(conn, "REPLACE INTO %s (id, %s) VALUES "
					"(%d, %d, '%s', '%s', '%s %s 0 %d %d "
					"%d %d', %d, %d)",
					db, fields, record_id, domain_id,
					domain, type, dotchomp(pns),
					hostmaster, refresh, retry, expire,
					ncttl, ttl, time(NULL));

			fcgx_p("Location: /records/?domain_id=%d&type=soa"
					"\r\n\r\n", domain_id);
			goto out;
		}
	}

	/* GET or unsuccessful POST */
	if (!form_err) {
		/* GET */
		char *domain;
		char *soa;
		char *item;
		char *htmp;

		res = sql_query(conn, "SELECT pdns.domains.name AS domain FROM "
				"pdns.domains WHERE pdns.domains.id = %d",
				domain_id);
		db_row = get_dbrow(res);
		domain = strdupa(get_var(db_row, "domain"));
		vl = add_html_var(vl, "domain", domain);
		free_vars(db_row);
		mysql_free_result(res);

		res = sql_query(conn, "SELECT pdns.records.content, "
				"pdns.records.ttl "
				"FROM pdns.records "
				"INNER JOIN pdns.domains ON "
				"(pdns.records.domain_id = "
				"pdns.domains.id) WHERE "
				"pdns.records.domain_id = %d AND "
				"pdns.records.id = %d",
				domain_id, record_id);
		db_row = get_dbrow(res);

		soa = strdupa(get_var(db_row, "content"));
		item = strsep(&soa, " ");
		vl = add_html_var(vl, "dax_pns", item);
		item = strsep(&soa, " ");

		/* Display hostmaster address as email address */
		htmp = alloca(strlen(item) + 1);
		vl = add_html_var(vl, "dax_hostmaster",
			hostmaster_to_email(item, htmp));

		item = strsep(&soa, " "); /* not showing serial here */
		item = strsep(&soa, " ");
		vl = add_html_var(vl, "dax_refresh", item);
		item = strsep(&soa, " ");
		vl = add_html_var(vl, "dax_retry", item);
		item = strsep(&soa, " ");
		vl = add_html_var(vl, "dax_expire", item);
		item = strsep(&soa, " ");
		vl = add_html_var(vl, "dax_ncttl", item);

		vl = add_html_var(vl, "dax_ttl", get_var(db_row, "ttl"));
		free_vars(db_row);
		mysql_free_result(res);
	} else {
		/* POST with errors */
		vl = add_html_var(vl, "domain", qvar("dax_domain"));
		vl = add_html_var(vl, "dax_pns", qvar("dax_pns"));
		vl = add_html_var(vl, "dax_hostmaster", qvar("dax_hostmaster"));
		vl = add_html_var(vl, "dax_refresh", qvar("dax_refresh"));
		vl = add_html_var(vl, "dax_retry", qvar("dax_retry"));
		vl = add_html_var(vl, "dax_expire", qvar("dax_expire"));
		vl = add_html_var(vl, "dax_ncttl", qvar("dax_ncttl"));
		vl = add_html_var(vl, "dax_ttl", qvar("dax_ttl"));
	}

	add_csrf_token(vl);
	fmtlist = TMPL_add_fmt(fmtlist, "de_xss", de_xss);
	send_template("templates/soa_record.tmpl", vl, fmtlist);
	TMPL_free_fmtlist(fmtlist);
out:
	TMPL_free_varlist(vl);
	free(pns);
	free(hostmaster);
	free(domain);
}

/*
 * /ns_record/
 *
 * HTML is in templates/ns_record.tmpl
 */
static void ns_record(void)
{
	int domain_id;
	int record_id = 0;
	int ttl;
	char *domain = NULL;
	char *content = NULL;
	bool form_err = false;
	MYSQL_RES *res;
	TMPL_varlist *vl = NULL;
	TMPL_fmtlist *fmtlist = NULL;
	GHashTable *db_row = NULL;

	domain_id = atoi(qvar("domain_id"));
	if (!is_domain_editable(domain_id, "domains"))
		goto out2;

	vl = add_html_var(vl, "domain_id", qvar("domain_id"));

	if (IS_SET(qvar("record_id"))) {
		record_id = atoi(qvar("record_id"));
		vl = add_html_var(vl, "record_id", qvar("record_id"));
	}

	if (IS_POST() && valid_csrf_token()) {
		ttl = atoi(qvar("dax_ttl"));
		domain = make_mysql_safe_string(qvar("domain"));
		content = make_mysql_safe_string(qvar("dax_content"));

		if (ttl < 60) {
			form_err = true;
			vl = add_html_var(vl, "ttl_error", "yes");
		}
		if (!is_valid_hostname(content)) {
			form_err = true;
			vl = add_html_var(vl, "content_error", "yes");
		}

		if (!form_err) {
			const char *db = "pdns.records";
			const char *fields =
				"domain_id, name, type, content, ttl, "
				"change_date";
			const char *type = "NS";

			content = dotchomp(content);
			if (IS_SET(qvar("update")))
				sql_query(conn, "REPLACE INTO %s (id, %s) "
					"VALUES "
					"(%d, %d, '%s', '%s', '%s', %d, %d)",
					db, fields, record_id, domain_id,
					domain, type, content, ttl,
					time(NULL));
			else
				sql_query(conn, "INSERT INTO %s (%s) VALUES "
					"(%d, '%s', '%s', '%s', %d, %d)",
					db, fields, domain_id, domain, type,
					content, ttl, time(NULL));

			fcgx_p("Location: /records/?domain_id=%d&type=ns#add"
					"\r\n\r\n", domain_id);
			goto out2;
		}
	}

	/* GET or unsuccessful POST */
	if (!form_err) {
		/* GET */
		char *domain;

		res = sql_query(conn, "SELECT pdns.domains.name AS domain FROM "
				"pdns.domains WHERE pdns.domains.id = %d",
				domain_id);
		db_row = get_dbrow(res);
		domain = strdupa(get_var(db_row, "domain"));
		vl = add_html_var(vl, "domain", domain);
		free_vars(db_row);
		mysql_free_result(res);

		if (!record_id) {
			vl = add_html_var(vl, "dax_ttl", "3600");
			goto out;
		}
		/* We are updating an existing record */
		res = sql_query(conn, "SELECT IF"
				"(pdns.records.name = pdns.domains.name, "
				"'', TRIM(TRAILING '.%s' FROM "
				"pdns.records.name)) AS name, "
				"pdns.records.content, "
				"pdns.records.ttl, "
				"pdns.records.prio FROM pdns.records "
				"INNER JOIN pdns.domains ON "
				"(pdns.records.domain_id = "
				"pdns.domains.id) WHERE "
				"pdns.records.domain_id = %d AND "
				"pdns.records.id = %d",
				domain, domain_id, record_id);
		db_row = get_dbrow(res);
		vl = add_html_var(vl, "dax_content", get_var(db_row,
					"content"));
		vl = add_html_var(vl, "dax_ttl", get_var(db_row, "ttl"));
		vl = add_html_var(vl, "update", "update");
		free_vars(db_row);
		mysql_free_result(res);
	} else {
		/* POST with errors */
		vl = add_html_var(vl, "domain", qvar("domain"));
		vl = add_html_var(vl, "dax_content", qvar("dax_content"));
		vl = add_html_var(vl, "dax_ttl", qvar("dax_ttl"));
		if (IS_SET(qvar("update")))
			vl = add_html_var(vl, "update", "update");
	}

out:
	add_csrf_token(vl);
	fmtlist = TMPL_add_fmt(fmtlist, "de_xss", de_xss);
	send_template("templates/ns_record.tmpl", vl, fmtlist);
	TMPL_free_fmtlist(fmtlist);
out2:
	TMPL_free_varlist(vl);
	free(domain);
	free(content);
}

/*
 * /a_record/
 *
 * HTML is in templates/a_record.tmpl
 */
static void a_record(void)
{
	int domain_id;
	int record_id = 0;
	int ttl;
	char *name = NULL;
	char *domain = NULL;
	char *content = NULL;
	bool form_err = false;
	MYSQL_RES *res;
	TMPL_varlist *vl = NULL;
	TMPL_fmtlist *fmtlist;
	GHashTable *db_row = NULL;

	domain_id = atoi(qvar("domain_id"));
	if (!is_domain_editable(domain_id, "domains"))
		goto out2;

	vl = add_html_var(vl, "domain_id", qvar("domain_id"));

	if (IS_SET(qvar("record_id"))) {
		record_id = atoi(qvar("record_id"));
		vl = add_html_var(vl, "record_id", qvar("record_id"));
	}

	if (IS_POST() && valid_csrf_token()) {
		ttl = atoi(qvar("dax_ttl"));
		name = make_mysql_safe_string(qvar("dax_hostname"));
		domain = make_mysql_safe_string(qvar("domain"));
		content = make_mysql_safe_string(qvar("dax_content"));

		if (ttl < 60) {
			form_err = true;
			vl = add_html_var(vl, "ttl_error", "yes");
		}
		/* Allow for an empty hostname field */
		if (IS_SET(name) && !is_valid_hostname(name)) {
			form_err = true;
			vl = add_html_var(vl, "hostname_error", "yes");
		}
		if (!is_valid_ipv4_addr(content)) {
			form_err = true;
			vl = add_html_var(vl, "content_error", "yes");
		}

		if (!form_err) {
			struct dom_rec_ent dre;

			dre.domain = domain;
			dre.name = dotchomp(name);
			dre.content = content;
			dre.type = "A";
			dre.prio = 0;
			dre.ttl = ttl;
			__dns_record_to_db(&dre, domain_id, record_id);

			fcgx_p("Location: /records/?domain_id=%d&type=a#add"
					"\r\n\r\n", domain_id);
			goto out2;
		}
	}

	/* GET or unsuccessful POST */
	if (!form_err) {
		/* GET */
		char *domain;

		res = sql_query(conn, "SELECT pdns.domains.name AS domain FROM "
				"pdns.domains WHERE pdns.domains.id = %d",
				domain_id);
		db_row = get_dbrow(res);
		domain = strdupa(get_var(db_row, "domain"));
		vl = add_html_var(vl, "domain", domain);
		free_vars(db_row);
		mysql_free_result(res);

		if (!record_id) {
			vl = add_html_var(vl, "dax_ttl", "3600");
			goto out;
		}
		/* We are updating an existing record */
		res = sql_query(conn, "SELECT IF"
				"(pdns.records.name = pdns.domains.name, "
				"'', TRIM(TRAILING '.%s' FROM "
				"pdns.records.name)) AS name, "
				"pdns.records.content, "
				"pdns.records.ttl, "
				"pdns.records.prio FROM pdns.records "
				"INNER JOIN pdns.domains ON "
				"(pdns.records.domain_id = "
				"pdns.domains.id) WHERE "
				"pdns.records.domain_id = %d AND "
				"pdns.records.id = %d",
				domain, domain_id, record_id);
		db_row = get_dbrow(res);
		vl = add_html_var(vl, "dax_hostname", get_var(db_row, "name"));
		vl = add_html_var(vl, "dax_content", get_var(db_row,
					"content"));
		vl = add_html_var(vl, "dax_ttl", get_var(db_row, "ttl"));
		vl = add_html_var(vl, "update", "update");
		free_vars(db_row);
		mysql_free_result(res);
	} else {
		/* POST with errors */
		vl = add_html_var(vl, "domain", qvar("domain"));
		vl = add_html_var(vl, "dax_hostname", qvar("dax_hostname"));
		vl = add_html_var(vl, "dax_content", qvar("dax_content"));
		vl = add_html_var(vl, "dax_ttl", qvar("dax_ttl"));
		if (IS_SET(qvar("update")))
			vl = add_html_var(vl, "update", "update");
	}

out:
	add_csrf_token(vl);
	fmtlist = TMPL_add_fmt(NULL, "de_xss", de_xss);
	send_template("templates/a_record.tmpl", vl, fmtlist);
	TMPL_free_fmtlist(fmtlist);
out2:
	TMPL_free_varlist(vl);
	free(name);
	free(domain);
	free(content);
}

/*
 * /aaaa_record/
 *
 * HTML is in templates/aaaa_record.tmpl
 */
static void aaaa_record(void)
{
	int domain_id;
	int record_id = 0;
	int ttl;
	char *name = NULL;
	char *domain = NULL;
	char *content = NULL;
	bool form_err = false;
	MYSQL_RES *res;
	TMPL_varlist *vl = NULL;
	TMPL_fmtlist *fmtlist = NULL;
	GHashTable *db_row = NULL;

	domain_id = atoi(qvar("domain_id"));
	if (!is_domain_editable(domain_id, "domains"))
		goto out2;

	vl = add_html_var(vl, "domain_id", qvar("domain_id"));

	if (IS_SET(qvar("record_id"))) {
		record_id = atoi(qvar("record_id"));
		vl = add_html_var(vl, "record_id", qvar("record_id"));
	}

	if (IS_POST() && valid_csrf_token()) {
		ttl = atoi(qvar("dax_ttl"));
		name = make_mysql_safe_string(qvar("dax_hostname"));
		domain = make_mysql_safe_string(qvar("domain"));
		content = make_mysql_safe_string(qvar("dax_content"));

		if (ttl < 60) {
			form_err = true;
			vl = add_html_var(vl, "ttl_error", "yes");
		}
		/* Allow for an empty hostname field */
		if (IS_SET(name) && !is_valid_hostname(name)) {
			form_err = true;
			vl = add_html_var(vl, "hostname_error", "yes");
		}
		if (!IS_SET(content) || !is_valid_ipv6_addr(content)) {
			form_err = true;
			vl = add_html_var(vl, "content_error", "yes");
		}

		if (!form_err) {
			struct dom_rec_ent dre;

			dre.domain = domain;
			dre.name = dotchomp(name);
			dre.content = content;
			dre.type = "AAAA";
			dre.prio = 0;
			dre.ttl = ttl;
			__dns_record_to_db(&dre, domain_id, record_id);

			fcgx_p("Location: /records/?domain_id=%d&type=aaaa#add"
					"\r\n\r\n", domain_id);
			goto out2;
		}
	}

	/* GET or unsuccessful POST */
	if (!form_err) {
		/* GET */
		char *domain;

		res = sql_query(conn, "SELECT pdns.domains.name AS domain FROM "
				"pdns.domains WHERE pdns.domains.id = %d",
				domain_id);
		db_row = get_dbrow(res);
		domain = strdupa(get_var(db_row, "domain"));
		vl = add_html_var(vl, "domain", domain);
		free_vars(db_row);
		mysql_free_result(res);

		if (!record_id) {
			vl = add_html_var(vl, "dax_ttl", "3600");
			goto out;
		}
		/* We are updating an existing record */
		res = sql_query(conn, "SELECT IF"
				"(pdns.records.name = pdns.domains.name, "
				"'', TRIM(TRAILING '.%s' FROM "
				"pdns.records.name)) AS name, "
				"pdns.records.content, "
				"pdns.records.ttl, "
				"pdns.records.prio FROM pdns.records "
				"INNER JOIN pdns.domains ON "
				"(pdns.records.domain_id = "
				"pdns.domains.id) WHERE "
				"pdns.records.domain_id = %d AND "
				"pdns.records.id = %d",
				domain, domain_id, record_id);
		db_row = get_dbrow(res);
		vl = add_html_var(vl, "dax_hostname", get_var(db_row, "name"));
		vl = add_html_var(vl, "dax_content", get_var(db_row,
					"content"));
		vl = add_html_var(vl, "dax_ttl", get_var(db_row, "ttl"));
		vl = add_html_var(vl, "update", "update");
		free_vars(db_row);
		mysql_free_result(res);
	} else {
		/* POST with errors */
		vl = add_html_var(vl, "domain", qvar("domain"));
		vl = add_html_var(vl, "dax_hostname", qvar("dax_hostname"));
		vl = add_html_var(vl, "dax_content", qvar("dax_content"));
		vl = add_html_var(vl, "dax_ttl", qvar("dax_ttl"));
		if (IS_SET(qvar("update")))
			vl = add_html_var(vl, "update", "update");
	}

out:
	add_csrf_token(vl);
	fmtlist = TMPL_add_fmt(fmtlist, "de_xss", de_xss);
	send_template("templates/aaaa_record.tmpl", vl, fmtlist);
	TMPL_free_fmtlist(fmtlist);
out2:
	TMPL_free_varlist(vl);
	free(name);
	free(domain);
	free(content);
}

/*
 * /cname_record/
 *
 * HTML is in templates/cname_record.tmpl
 */
static void cname_record(void)
{
	int domain_id;
	int record_id = 0;
	int ttl;
	char *name = NULL;
	char *domain = NULL;
	char *content = NULL;
	bool form_err = false;
	MYSQL_RES *res;
	TMPL_varlist *vl = NULL;
	TMPL_fmtlist *fmtlist = NULL;
	GHashTable *db_row = NULL;

	domain_id = atoi(qvar("domain_id"));
	if (!is_domain_editable(domain_id, "domains"))
		goto out2;

	vl = add_html_var(vl, "domain_id", qvar("domain_id"));

	if (IS_SET(qvar("record_id"))) {
		record_id = atoi(qvar("record_id"));
		vl = add_html_var(vl, "record_id", qvar("record_id"));
	}

	if (IS_POST() && valid_csrf_token()) {
		ttl = atoi(qvar("dax_ttl"));
		name = make_mysql_safe_string(qvar("dax_hostname"));
		domain = make_mysql_safe_string(qvar("domain"));
		content = make_mysql_safe_string(qvar("dax_content"));

		if (ttl < 60) {
			form_err = true;
			vl = add_html_var(vl, "ttl_error", "yes");
		}
		if (!is_valid_hostname(name)) {
			form_err = true;
			vl = add_html_var(vl, "hostname_error", "yes");
		}
		/*
		 * CNAME RDATA should allow entries like:
		 * 129.128/26.2.0.192.in-addr.arpa. for reverse CIDR
		 * lookups.
		 */
		if (!IS_SET(content)) {
			form_err = true;
			vl = add_html_var(vl, "content_error", "yes");
		}

		if (!form_err) {
			struct dom_rec_ent dre;

			dre.domain = domain;
			dre.name = dotchomp(name);
			dre.content = dotchomp(content);
			dre.type = "CNAME";
			dre.prio = 0;
			dre.ttl = ttl;
			__dns_record_to_db(&dre, domain_id, record_id);

			fcgx_p("Location: /records/?domain_id=%d&type=cname#add"
					"\r\n\r\n", domain_id);
			goto out2;
		}
	}

	/* GET or unsuccessful POST */
	if (!form_err) {
		/* GET */
		char *domain;

		res = sql_query(conn, "SELECT pdns.domains.name AS domain FROM "
				"pdns.domains WHERE pdns.domains.id = %d",
				domain_id);
		db_row = get_dbrow(res);
		domain = strdupa(get_var(db_row, "domain"));
		vl = add_html_var(vl, "domain", domain);
		free_vars(db_row);
		mysql_free_result(res);

		if (!record_id) {
			vl = add_html_var(vl, "dax_ttl", "3600");
			goto out;
		}
		/* We are updating an existing record */
		res = sql_query(conn, "SELECT IF"
				"(pdns.records.name = pdns.domains.name, "
				"'', TRIM(TRAILING '.%s' FROM "
				"pdns.records.name)) AS name, "
				"pdns.records.content, "
				"pdns.records.ttl, "
				"pdns.records.prio FROM pdns.records "
				"INNER JOIN pdns.domains ON "
				"(pdns.records.domain_id = "
				"pdns.domains.id) WHERE "
				"pdns.records.domain_id = %d AND "
				"pdns.records.id = %d",
				domain, domain_id, record_id);
		db_row = get_dbrow(res);
		vl = add_html_var(vl, "dax_hostname", get_var(db_row, "name"));
		vl = add_html_var(vl, "dax_content", get_var(db_row,
					"content"));
		vl = add_html_var(vl, "dax_ttl", get_var(db_row, "ttl"));
		vl = add_html_var(vl, "update", "update");
		free_vars(db_row);
		mysql_free_result(res);
	} else {
		/* POST with errors */
		vl = add_html_var(vl, "domain", qvar("domain"));
		vl = add_html_var(vl, "dax_hostname", qvar("dax_hostname"));
		vl = add_html_var(vl, "dax_content", qvar("dax_content"));
		vl = add_html_var(vl, "dax_ttl", qvar("dax_ttl"));
		if (IS_SET(qvar("update")))
			vl = add_html_var(vl, "update", "update");
	}

out:
	add_csrf_token(vl);
	fmtlist = TMPL_add_fmt(fmtlist, "de_xss", de_xss);
	send_template("templates/cname_record.tmpl", vl, fmtlist);
	TMPL_free_fmtlist(fmtlist);
out2:
	TMPL_free_varlist(vl);
	free(name);
	free(domain);
	free(content);
}

/*
 * /loc_record/
 *
 * HTML is in templates/loc_record.tmpl
 */
static void loc_record(void)
{
	int domain_id;
	int record_id = 0;
	int ttl;
	char *name = NULL;
	char *domain = NULL;
	char *content = NULL;
	bool form_err = false;
	MYSQL_RES *res;
	TMPL_varlist *vl = NULL;
	TMPL_fmtlist *fmtlist = NULL;
	GHashTable *db_row = NULL;

	domain_id = atoi(qvar("domain_id"));
	if (!is_domain_editable(domain_id, "domains"))
		goto out2;

	vl = add_html_var(vl, "domain_id", qvar("domain_id"));

	if (IS_SET(qvar("record_id"))) {
		record_id = atoi(qvar("record_id"));
		vl = add_html_var(vl, "record_id", qvar("record_id"));
	}

	if (IS_POST() && valid_csrf_token()) {
		ttl = atoi(qvar("dax_ttl"));
		name = make_mysql_safe_string(qvar("dax_hostname"));
		domain = make_mysql_safe_string(qvar("domain"));
		content = make_mysql_safe_string(qvar("dax_loc"));

		if (ttl < 60) {
			form_err = true;
			vl = add_html_var(vl, "ttl_error", "yes");
		}
		/* Allow an empty hostname field */
		if (IS_SET(name) && !is_valid_hostname(name)) {
			form_err = true;
			vl = add_html_var(vl, "hostname_error", "yes");
		}
		if (!IS_SET(content)) {
			form_err = true;
			vl = add_html_var(vl, "content_error", "yes");
		}

		if (!form_err) {
			struct dom_rec_ent dre;

			dre.domain = domain;
			dre.name = dotchomp(name);
			dre.content = dotchomp(content);
			dre.type = "LOC";
			dre.prio = 0;
			dre.ttl = ttl;
			__dns_record_to_db(&dre, domain_id, record_id);

			fcgx_p("Location: /records/?domain_id=%d&type=loc#add"
					"\r\n\r\n", domain_id);
			goto out2;
		}
	}

	/* GET or unsuccessful POST */
	if (!form_err) {
		/* GET */
		char *domain;

		res = sql_query(conn, "SELECT pdns.domains.name AS domain FROM "
				"pdns.domains WHERE pdns.domains.id = %d",
				domain_id);
		db_row = get_dbrow(res);
		domain = strdupa(get_var(db_row, "domain"));
		vl = add_html_var(vl, "domain", domain);
		free_vars(db_row);
		mysql_free_result(res);

		if (!record_id) {
			vl = add_html_var(vl, "dax_ttl", "3600");
			goto out;
		}
		/* We are updating an existing record */
		res = sql_query(conn, "SELECT IF"
				"(pdns.records.name = pdns.domains.name, "
				"'', TRIM(TRAILING '.%s' FROM "
				"pdns.records.name)) AS name, "
				"pdns.records.content, "
				"pdns.records.ttl, "
				"pdns.records.prio FROM pdns.records "
				"INNER JOIN pdns.domains ON "
				"(pdns.records.domain_id = "
				"pdns.domains.id) WHERE "
				"pdns.records.domain_id = %d AND "
				"pdns.records.id = %d",
				domain, domain_id, record_id);
		db_row = get_dbrow(res);
		vl = add_html_var(vl, "dax_hostname", get_var(db_row, "name"));
		vl = add_html_var(vl, "dax_loc", get_var(db_row, "content"));
		vl = add_html_var(vl, "dax_ttl", get_var(db_row, "ttl"));
		vl = add_html_var(vl, "update", "update");
		free_vars(db_row);
		mysql_free_result(res);
	} else {
		/* POST with errors */
		vl = add_html_var(vl, "domain", qvar("domain"));
		vl = add_html_var(vl, "dax_hostname", qvar("dax_hostname"));
		vl = add_html_var(vl, "dax_loc", qvar("dax_loc"));
		vl = add_html_var(vl, "dax_ttl", qvar("dax_ttl"));
		if (IS_SET(qvar("update")))
			vl = add_html_var(vl, "update", "update");
	}

out:
	add_csrf_token(vl);
	fmtlist = TMPL_add_fmt(fmtlist, "de_xss", de_xss);
	send_template("templates/loc_record.tmpl", vl, fmtlist);
	TMPL_free_fmtlist(fmtlist);
out2:
	TMPL_free_varlist(vl);
	free(name);
	free(domain);
	free(content);
}

/*
 * /mx_record/
 *
 * HTML is in templates/mx_record.tmpl
 */
static void mx_record(void)
{
	int domain_id;
	int record_id = 0;
	int ttl;
	int prio;
	char *name = NULL;
	char *domain = NULL;
	char *content = NULL;
	bool null_mx = false;
	bool form_err = false;
	MYSQL_RES *res;
	TMPL_varlist *vl = NULL;
	TMPL_fmtlist *fmtlist = NULL;
	GHashTable *db_row = NULL;

	domain_id = atoi(qvar("domain_id"));
	if (!is_domain_editable(domain_id, "domains"))
		goto out2;

	vl = add_html_var(vl, "domain_id", qvar("domain_id"));

	if (IS_SET(qvar("record_id"))) {
		record_id = atoi(qvar("record_id"));
		vl = add_html_var(vl, "record_id", qvar("record_id"));
	}

	if (IS_POST() && valid_csrf_token()) {
		ttl = atoi(qvar("dax_ttl"));
		prio = atoi(qvar("dax_prio"));
		name = make_mysql_safe_string(qvar("dax_hostname"));
		domain = make_mysql_safe_string(qvar("domain"));
		content = make_mysql_safe_string(qvar("dax_content"));

		if (ttl < 60) {
			form_err = true;
			vl = add_html_var(vl, "ttl_error", "yes");
		}
		/* Allow for an empty hostname field */
		if (IS_SET(name) && !is_valid_hostname(name)) {
			form_err = true;
			vl = add_html_var(vl, "hostname_error", "yes");
		}
		/* Allow for NULL MX records, MX host would be '.' */
		if (strcmp(content, ".") == 0)
			null_mx = true;
		if (!null_mx && !is_valid_hostname(content)) {
			form_err = true;
			vl = add_html_var(vl, "content_error", "yes");
		}

		if (!form_err) {
			struct dom_rec_ent dre;

                        dre.domain = domain;
                        dre.name = dotchomp(name);
                        dre.type = "MX";
                        dre.prio = prio;
                        dre.ttl = ttl;

			if (!null_mx)
				dre.content = dotchomp(content);
			else
				dre.content = content;

			__dns_record_to_db(&dre, domain_id, record_id);

			fcgx_p("Location: /records/?domain_id=%d&type=mx#add"
					"\r\n\r\n", domain_id);
			goto out2;
		}
	}

	/* GET or unsuccessful POST */
	if (!form_err) {
		/* GET */
		char *domain;

		res = sql_query(conn, "SELECT pdns.domains.name AS domain FROM "
				"pdns.domains WHERE pdns.domains.id = %d",
				domain_id);
		db_row = get_dbrow(res);
		domain = strdupa(get_var(db_row, "domain"));
		vl = add_html_var(vl, "domain", domain);
		free_vars(db_row);
		mysql_free_result(res);

		if (!record_id) {
			vl = add_html_var(vl, "dax_prio", "10");
			vl = add_html_var(vl, "dax_ttl", "3600");
			goto out;
		}
		/* We are updating an existing record */
		res = sql_query(conn, "SELECT IF"
				"(pdns.records.name = pdns.domains.name, "
				"'', TRIM(TRAILING '.%s' FROM "
				"pdns.records.name)) AS name, "
				"pdns.records.content, "
				"pdns.records.ttl, "
				"pdns.records.prio FROM pdns.records "
				"INNER JOIN pdns.domains ON "
				"(pdns.records.domain_id = "
				"pdns.domains.id) WHERE "
				"pdns.records.domain_id = %d AND "
				"pdns.records.id = %d",
				domain, domain_id, record_id);
		db_row = get_dbrow(res);
		vl = add_html_var(vl, "dax_hostname", get_var(db_row, "name"));
		vl = add_html_var(vl, "dax_content", get_var(db_row,
					"content"));
		vl = add_html_var(vl, "dax_prio", get_var(db_row, "prio"));
		vl = add_html_var(vl, "dax_ttl", get_var(db_row, "ttl"));
		vl = add_html_var(vl, "update", "update");
		free_vars(db_row);
		mysql_free_result(res);
	} else {
		/* POST with errors */
		vl = add_html_var(vl, "domain", qvar("domain"));
		vl = add_html_var(vl, "dax_hostname", qvar("dax_hostname"));
		vl = add_html_var(vl, "dax_content", qvar("dax_content"));
		vl = add_html_var(vl, "dax_prio", qvar("dax_prio"));
		vl = add_html_var(vl, "dax_ttl", qvar("dax_ttl"));
		if (IS_SET(qvar("update")))
			vl = add_html_var(vl, "update", "update");
	}

out:
	add_csrf_token(vl);
	fmtlist = TMPL_add_fmt(fmtlist, "de_xss", de_xss);
	send_template("templates/mx_record.tmpl", vl, fmtlist);
	TMPL_free_fmtlist(fmtlist);
out2:
	TMPL_free_varlist(vl);
	free(name);
	free(domain);
	free(content);
}

/*
 * /naptr_record/
 *
 * HTML is in templates/naptr_record.tmpl
 */
static void naptr_record(void)
{
	int domain_id;
	int record_id = 0;
	int ttl;
	char *name = NULL;
	char *domain = NULL;
	char *content = NULL;
	bool form_err = false;
	MYSQL_RES *res;
	TMPL_varlist *vl = NULL;
	TMPL_fmtlist *fmtlist = NULL;
	GHashTable *db_row = NULL;

	domain_id = atoi(qvar("domain_id"));
	if (!is_domain_editable(domain_id, "domains"))
		goto out2;

	vl = add_html_var(vl, "domain_id", qvar("domain_id"));

	if (IS_SET(qvar("record_id"))) {
		record_id = atoi(qvar("record_id"));
		vl = add_html_var(vl, "record_id", qvar("record_id"));
	}

	if (IS_POST() && valid_csrf_token()) {
		ttl = atoi(qvar("dax_ttl"));
		name = make_mysql_safe_string(qvar("dax_hostname"));
		domain = make_mysql_safe_string(qvar("domain"));
		content = make_mysql_safe_string(qvar("dax_naptr"));

		if (ttl < 60) {
			form_err = true;
			vl = add_html_var(vl, "ttl_error", "yes");
		}
		/* Allow an empty hostname field */
		if (IS_SET(name) && !is_valid_hostname(name)) {
			form_err = true;
			vl = add_html_var(vl, "hostname_error", "yes");
		}
		if (!IS_SET(content)) {
			form_err = true;
			vl = add_html_var(vl, "content_error", "yes");
		}

		if (!form_err) {
			struct dom_rec_ent dre;

			dre.domain = domain;
			dre.name = dotchomp(name);
			dre.content = dotchomp(content);
			dre.type = "NAPTR";
			dre.prio = 0;
			dre.ttl = ttl;
			__dns_record_to_db(&dre, domain_id, record_id);

			fcgx_p("Location: /records/?domain_id=%d&type=naptr#add"
					"\r\n\r\n", domain_id);
			goto out2;
		}
	}

	/* GET or unsuccessful POST */
	if (!form_err) {
		/* GET */
		char *domain;

		res = sql_query(conn, "SELECT pdns.domains.name AS domain FROM "
				"pdns.domains WHERE pdns.domains.id = %d",
				domain_id);
		db_row = get_dbrow(res);
		domain = strdupa(get_var(db_row, "domain"));
		vl = add_html_var(vl, "domain", domain);
		free_vars(db_row);
		mysql_free_result(res);

		if (!record_id) {
			vl = add_html_var(vl, "dax_ttl", "3600");
			goto out;
		}
		/* We are updating an existing record */
		res = sql_query(conn, "SELECT IF"
				"(pdns.records.name = pdns.domains.name, "
				"'', TRIM(TRAILING '.%s' FROM "
				"pdns.records.name)) AS name, "
				"pdns.records.content, "
				"pdns.records.ttl, "
				"pdns.records.prio FROM pdns.records "
				"INNER JOIN pdns.domains ON "
				"(pdns.records.domain_id = "
				"pdns.domains.id) WHERE "
				"pdns.records.domain_id = %d AND "
				"pdns.records.id = %d",
				domain, domain_id, record_id);
		db_row = get_dbrow(res);
		vl = add_html_var(vl, "dax_hostname", get_var(db_row, "name"));
		vl = add_html_var(vl, "dax_naptr", get_var(db_row, "content"));
		vl = add_html_var(vl, "dax_ttl", get_var(db_row, "ttl"));
		vl = add_html_var(vl, "update", "update");
		free_vars(db_row);
		mysql_free_result(res);
	} else {
		/* POST with errors */
		vl = add_html_var(vl, "domain", qvar("domain"));
		vl = add_html_var(vl, "dax_hostname", qvar("dax_hostname"));
		vl = add_html_var(vl, "dax_naptr", qvar("dax_naptr"));
		vl = add_html_var(vl, "dax_ttl", qvar("dax_ttl"));
		if (IS_SET(qvar("update")))
			vl = add_html_var(vl, "update", "update");
	}

out:
	add_csrf_token(vl);
	fmtlist = TMPL_add_fmt(fmtlist, "de_xss", de_xss);
	send_template("templates/naptr_record.tmpl", vl, fmtlist);
	TMPL_free_fmtlist(fmtlist);
out2:
	TMPL_free_varlist(vl);
	free(name);
	free(domain);
	free(content);
}

/*
 * /ptr_record/
 *
 * HTML is in templates/ptr_record.tmpl
 */
static void ptr_record(void)
{
	int domain_id;
	int record_id = 0;
	int ttl;
	char *name = NULL;
	char *domain = NULL;
	char *content = NULL;
	bool form_err = false;
	MYSQL_RES *res;
	TMPL_varlist *vl = NULL;
	TMPL_fmtlist *fmtlist = NULL;
	GHashTable *db_row = NULL;

	domain_id = atoi(qvar("domain_id"));
	if (!is_domain_editable(domain_id, "domains"))
		goto out2;

	vl = add_html_var(vl, "domain_id", qvar("domain_id"));

	if (IS_SET(qvar("record_id"))) {
		record_id = atoi(qvar("record_id"));
		vl = add_html_var(vl, "record_id", qvar("record_id"));
	}

	if (IS_POST() && valid_csrf_token()) {
		ttl = atoi(qvar("dax_ttl"));
		name = make_mysql_safe_string(qvar("dax_hostname"));
		domain = make_mysql_safe_string(qvar("domain"));
		content = make_mysql_safe_string(qvar("dax_content"));

		if (ttl < 60) {
			form_err = true;
			vl = add_html_var(vl, "ttl_error", "yes");
		}
		/* Allow for an empty hostname field */
		if (!is_valid_hostname(name)) {
			form_err = true;
			vl = add_html_var(vl, "hostname_error", "yes");
		}
		if (!is_valid_hostname(content)) {
			form_err = true;
			vl = add_html_var(vl, "content_error", "yes");
		}

		if (!form_err) {
			struct dom_rec_ent dre;

			dre.domain = domain;
			dre.name = dotchomp(name);
			dre.content = dotchomp(content);
			dre.type = "PTR";
			dre.prio = 0;
			dre.ttl = ttl;
			__dns_record_to_db(&dre, domain_id, record_id);

			fcgx_p("Location: /records/?domain_id=%d&type=ptr#add"
					"\r\n\r\n", domain_id);
			goto out2;
		}
	}

	/* GET or unsuccessful POST */
	if (!form_err) {
		/* GET */
		char *domain;

		res = sql_query(conn, "SELECT pdns.domains.name AS domain FROM "
				"pdns.domains WHERE pdns.domains.id = %d",
				domain_id);
		db_row = get_dbrow(res);
		domain = strdupa(get_var(db_row, "domain"));
		vl = add_html_var(vl, "domain", domain);
		free_vars(db_row);
		mysql_free_result(res);

		if (!record_id) {
			vl = add_html_var(vl, "dax_ttl", "3600");
			goto out;
		}
		/* We are updating an existing record */
		res = sql_query(conn, "SELECT IF"
				"(pdns.records.name = pdns.domains.name, "
				"'', TRIM(TRAILING '.%s' FROM "
				"pdns.records.name)) AS name, "
				"pdns.records.content, "
				"pdns.records.ttl, "
				"pdns.records.prio FROM pdns.records "
				"INNER JOIN pdns.domains ON "
				"(pdns.records.domain_id = "
				"pdns.domains.id) WHERE "
				"pdns.records.domain_id = %d AND "
				"pdns.records.id = %d",
				domain, domain_id, record_id);
		db_row = get_dbrow(res);
		vl = add_html_var(vl, "dax_hostname", get_var(db_row, "name"));
		vl = add_html_var(vl, "dax_content", get_var(db_row,
					"content"));
		vl = add_html_var(vl, "dax_ttl", get_var(db_row, "ttl"));
		vl = add_html_var(vl, "update", "update");
		free_vars(db_row);
		mysql_free_result(res);
	} else {
		/* POST with errors */
		vl = add_html_var(vl, "domain", qvar("domain"));
		vl = add_html_var(vl, "dax_hostname", qvar("dax_hostname"));
		vl = add_html_var(vl, "dax_content", qvar("dax_content"));
		vl = add_html_var(vl, "dax_ttl", qvar("dax_ttl"));
		if (IS_SET(qvar("update")))
			vl = add_html_var(vl, "update", "update");
	}

out:
	add_csrf_token(vl);
	fmtlist = TMPL_add_fmt(fmtlist, "de_xss", de_xss);
	send_template("templates/ptr_record.tmpl", vl, fmtlist);
	TMPL_free_fmtlist(fmtlist);
out2:
	TMPL_free_varlist(vl);
	free(name);
	free(domain);
	free(content);
}

/*
 * /rp_record/
 *
 * HTML is in templates/rp_record.tmpl
 */
static void rp_record(void)
{
	int domain_id;
	int record_id = 0;
	int ttl;
	char *name = NULL;
	char *domain = NULL;
	char *content = NULL;
	bool form_err = false;
	MYSQL_RES *res;
	TMPL_varlist *vl = NULL;
	TMPL_fmtlist *fmtlist = NULL;
	GHashTable *db_row = NULL;

	domain_id = atoi(qvar("domain_id"));
	if (!is_domain_editable(domain_id, "domains"))
		goto out2;

	vl = add_html_var(vl, "domain_id", qvar("domain_id"));

	if (IS_SET(qvar("record_id"))) {
		record_id = atoi(qvar("record_id"));
		vl = add_html_var(vl, "record_id", qvar("record_id"));
	}

	if (IS_POST() && valid_csrf_token()) {
		ttl = atoi(qvar("dax_ttl"));
		name = make_mysql_safe_string(qvar("dax_hostname"));
		domain = make_mysql_safe_string(qvar("domain"));
		content = make_mysql_safe_string(qvar("dax_rp"));

		if (ttl < 60) {
			form_err = true;
			vl = add_html_var(vl, "ttl_error", "yes");
		}
		/* Allow an empty hostname field */
		if (IS_SET(name) && !is_valid_hostname(name)) {
			form_err = true;
			vl = add_html_var(vl, "hostname_error", "yes");
		}
		if (!IS_SET(content)) {
			form_err = true;
			vl = add_html_var(vl, "content_error", "yes");
		}

		if (!form_err) {
			struct dom_rec_ent dre;

			dre.domain = domain;
			dre.name = dotchomp(name);
			dre.content = content;
			dre.type = "RP";
			dre.prio = 0;
			dre.ttl = ttl;
			__dns_record_to_db(&dre, domain_id, record_id);

			fcgx_p("Location: /records/?domain_id=%d&type=rp#add"
					"\r\n\r\n", domain_id);
			goto out2;
		}
	}

	/* GET or unsuccessful POST */
	if (!form_err) {
		/* GET */
		char *domain;

		res = sql_query(conn, "SELECT pdns.domains.name AS domain FROM "
				"pdns.domains WHERE pdns.domains.id = %d",
				domain_id);
		db_row = get_dbrow(res);
		domain = strdupa(get_var(db_row, "domain"));
		vl = add_html_var(vl, "domain", domain);
		free_vars(db_row);
		mysql_free_result(res);

		if (!record_id) {
			vl = add_html_var(vl, "dax_ttl", "3600");
			goto out;
		}
		/* We are updating an existing record */
		res = sql_query(conn, "SELECT IF"
				"(pdns.records.name = pdns.domains.name, "
				"'', TRIM(TRAILING '.%s' FROM "
				"pdns.records.name)) AS name, "
				"pdns.records.content, "
				"pdns.records.ttl, "
				"pdns.records.prio FROM pdns.records "
				"INNER JOIN pdns.domains ON "
				"(pdns.records.domain_id = "
				"pdns.domains.id) WHERE "
				"pdns.records.domain_id = %d AND "
				"pdns.records.id = %d",
				domain, domain_id, record_id);
		db_row = get_dbrow(res);
		vl = add_html_var(vl, "dax_hostname", get_var(db_row, "name"));
		vl = add_html_var(vl, "dax_rp", get_var(db_row, "content"));
		vl = add_html_var(vl, "dax_ttl", get_var(db_row, "ttl"));
		vl = add_html_var(vl, "update", "update");
		free_vars(db_row);
		mysql_free_result(res);
	} else {
		/* POST with errors */
		vl = add_html_var(vl, "domain", qvar("domain"));
		vl = add_html_var(vl, "dax_hostname", qvar("dax_hostname"));
		vl = add_html_var(vl, "dax_rp", qvar("dax_rp"));
		vl = add_html_var(vl, "dax_ttl", qvar("dax_ttl"));
		if (IS_SET(qvar("update")))
			vl = add_html_var(vl, "update", "update");
	}

out:
	add_csrf_token(vl);
	fmtlist = TMPL_add_fmt(fmtlist, "de_xss", de_xss);
	send_template("templates/rp_record.tmpl", vl, fmtlist);
	TMPL_free_fmtlist(fmtlist);
out2:
	TMPL_free_varlist(vl);
	free(name);
	free(domain);
	free(content);
}

/*
 * /spf_record/
 *
 * HTML is in templates/spf_record.tmpl
 */
static void spf_record(void)
{
	int domain_id;
	int record_id = 0;
	int ttl;
	char *name = NULL;
	char *domain = NULL;
	char *content = NULL;
	bool form_err = false;
	MYSQL_RES *res;
	TMPL_varlist *vl = NULL;
	TMPL_fmtlist *fmtlist = NULL;
	GHashTable *db_row = NULL;

	domain_id = atoi(qvar("domain_id"));
	if (!is_domain_editable(domain_id, "domains"))
		goto out2;

	vl = add_html_var(vl, "domain_id", qvar("domain_id"));

	if (IS_SET(qvar("record_id"))) {
		record_id = atoi(qvar("record_id"));
		vl = add_html_var(vl, "record_id", qvar("record_id"));
	}

	if (IS_POST() && valid_csrf_token()) {
		ttl = atoi(qvar("dax_ttl"));
		name = make_mysql_safe_string(qvar("dax_hostname"));
		domain = make_mysql_safe_string(qvar("domain"));
		content = make_mysql_safe_string(qvar("dax_spf"));

		if (ttl < 60) {
			form_err = true;
			vl = add_html_var(vl, "ttl_error", "yes");
		}
		/* Allow an empty hostname field */
		if (IS_SET(name) && !is_valid_hostname(name)) {
			form_err = true;
			vl = add_html_var(vl, "hostname_error", "yes");
		}
		if (!IS_SET(content)) {
			form_err = true;
			vl = add_html_var(vl, "content_error", "yes");
		}

		if (!form_err) {
			struct dom_rec_ent dre;

			dre.domain = domain;
			dre.name = dotchomp(name);
			dre.content = content;
			dre.type = "SPF";
			dre.prio = 0;
			dre.ttl = ttl;
			__dns_record_to_db(&dre, domain_id, record_id);

			fcgx_p("Location: /records/?domain_id=%d&type=spf#add"
					"\r\n\r\n", domain_id);
			goto out2;
		}
	}

	/* GET or unsuccessful POST */
	if (!form_err) {
		/* GET */
		char *domain;

		res = sql_query(conn, "SELECT pdns.domains.name AS domain FROM "
				"pdns.domains WHERE pdns.domains.id = %d",
				domain_id);
		db_row = get_dbrow(res);
		domain = strdupa(get_var(db_row, "domain"));
		vl = add_html_var(vl, "domain", domain);
		free_vars(db_row);
		mysql_free_result(res);

		if (!record_id) {
			vl = add_html_var(vl, "dax_ttl", "3600");
			goto out;
		}
		/* We are updating an existing record */
		res = sql_query(conn, "SELECT IF"
				"(pdns.records.name = pdns.domains.name, "
				"'', TRIM(TRAILING '.%s' FROM "
				"pdns.records.name)) AS name, "
				"pdns.records.content, "
				"pdns.records.ttl, "
				"pdns.records.prio FROM pdns.records "
				"INNER JOIN pdns.domains ON "
				"(pdns.records.domain_id = "
				"pdns.domains.id) WHERE "
				"pdns.records.domain_id = %d AND "
				"pdns.records.id = %d",
				domain, domain_id, record_id);
		db_row = get_dbrow(res);
		vl = add_html_var(vl, "dax_hostname", get_var(db_row, "name"));
		vl = add_html_var(vl, "dax_spf", get_var(db_row, "content"));
		vl = add_html_var(vl, "dax_ttl", get_var(db_row, "ttl"));
		vl = add_html_var(vl, "update", "update");
		free_vars(db_row);
		mysql_free_result(res);
	} else {
		/* POST with errors */
		vl = add_html_var(vl, "domain", qvar("domain"));
		vl = add_html_var(vl, "dax_hostname", qvar("dax_hostname"));
		vl = add_html_var(vl, "dax_spf", qvar("dax_spf"));
		vl = add_html_var(vl, "dax_ttl", qvar("dax_ttl"));
		if (IS_SET(qvar("update")))
			vl = add_html_var(vl, "update", "update");
	}

out:
	add_csrf_token(vl);
	fmtlist = TMPL_add_fmt(fmtlist, "de_xss", de_xss);
	send_template("templates/spf_record.tmpl", vl, fmtlist);
	TMPL_free_fmtlist(fmtlist);
out2:
	TMPL_free_varlist(vl);
	free(name);
	free(domain);
	free(content);
}

/*
 * /srv_record/
 *
 * HTML is in templates/srv_record.tmpl
 */
static void srv_record(void)
{
	int domain_id;
	int record_id = 0;
	int prio;
	int ttl;
	char *name = NULL;
	char *domain = NULL;
	char *content = NULL;
	bool form_err = false;
	MYSQL_RES *res;
	TMPL_varlist *vl = NULL;
	TMPL_fmtlist *fmtlist = NULL;
	GHashTable *db_row = NULL;

	domain_id = atoi(qvar("domain_id"));
	if (!is_domain_editable(domain_id, "domains"))
		goto out2;

	vl = add_html_var(vl, "domain_id", qvar("domain_id"));

	if (IS_SET(qvar("record_id"))) {
		record_id = atoi(qvar("record_id"));
		vl = add_html_var(vl, "record_id", qvar("record_id"));
	}

	if (IS_POST() && valid_csrf_token()) {
		prio = atoi(qvar("dax_prio"));
		ttl = atoi(qvar("dax_ttl"));
		name = make_mysql_safe_string(qvar("dax_hostname"));
		domain = make_mysql_safe_string(qvar("domain"));
		content = make_mysql_safe_string(qvar("dax_srv"));

		if (ttl < 60) {
			form_err = true;
			vl = add_html_var(vl, "ttl_error", "yes");
		}
		if (!IS_SET(name)) {
			form_err = true;
			vl = add_html_var(vl, "hostname_error", "yes");
		}
		if (!IS_SET(content)) {
			form_err = true;
			vl = add_html_var(vl, "content_error", "yes");
		}

		if (!form_err) {
			struct dom_rec_ent dre;

			dre.domain = domain;
			dre.name = dotchomp(name);
			dre.content = dotchomp(content);
			dre.type = "SRV";
			dre.prio = prio;
			dre.ttl = ttl;
			__dns_record_to_db(&dre, domain_id, record_id);

			fcgx_p("Location: /records/?domain_id=%d&type=srv#add"
					"\r\n\r\n", domain_id);
			goto out2;
		}
	}

	/* GET or unsuccessful POST */
	if (!form_err) {
		/* GET */
		char *domain;

		res = sql_query(conn, "SELECT pdns.domains.name AS domain FROM "
				"pdns.domains WHERE pdns.domains.id = %d",
				domain_id);
		db_row = get_dbrow(res);
		domain = strdupa(get_var(db_row, "domain"));
		vl = add_html_var(vl, "domain", domain);
		free_vars(db_row);
		mysql_free_result(res);

		if (!record_id) {
			vl = add_html_var(vl, "dax_ttl", "3600");
			vl = add_html_var(vl, "dax_prio", "0");
			goto out;
		}
		/* We are updating an existing record */
		res = sql_query(conn, "SELECT IF"
				"(pdns.records.name = pdns.domains.name, "
				"'', TRIM(TRAILING '.%s' FROM "
				"pdns.records.name)) AS name, "
				"pdns.records.content, "
				"pdns.records.ttl, "
				"pdns.records.prio FROM pdns.records "
				"INNER JOIN pdns.domains ON "
				"(pdns.records.domain_id = "
				"pdns.domains.id) WHERE "
				"pdns.records.domain_id = %d AND "
				"pdns.records.id = %d",
				domain, domain_id, record_id);
		db_row = get_dbrow(res);
		vl = add_html_var(vl, "dax_hostname", get_var(db_row, "name"));
		vl = add_html_var(vl, "dax_srv", get_var(db_row, "content"));
		vl = add_html_var(vl, "dax_prio", get_var(db_row, "prio"));
		vl = add_html_var(vl, "dax_ttl", get_var(db_row, "ttl"));
		vl = add_html_var(vl, "update", "update");
		free_vars(db_row);
		mysql_free_result(res);
	} else {
		/* POST with errors */
		vl = add_html_var(vl, "domain", qvar("domain"));
		vl = add_html_var(vl, "dax_hostname", qvar("dax_hostname"));
		vl = add_html_var(vl, "dax_srv", qvar("dax_srv"));
		vl = add_html_var(vl, "dax_prio", qvar("dax_prio"));
		vl = add_html_var(vl, "dax_ttl", qvar("dax_ttl"));
		if (IS_SET(qvar("update")))
			vl = add_html_var(vl, "update", "update");
	}

out:
	add_csrf_token(vl);
	fmtlist = TMPL_add_fmt(fmtlist, "de_xss", de_xss);
	send_template("templates/srv_record.tmpl", vl, fmtlist);
	TMPL_free_fmtlist(fmtlist);
out2:
	TMPL_free_varlist(vl);
	free(name);
	free(domain);
	free(content);
}

/*
 * /txt_record/
 *
 * HTML is in templates/txt_record.tmpl
 */
static void txt_record(void)
{
	int domain_id;
	int record_id = 0;
	int ttl;
	char *name = NULL;
	char *domain = NULL;
	char *content = NULL;
	bool form_err = false;
	MYSQL_RES *res;
	TMPL_varlist *vl = NULL;
	TMPL_fmtlist *fmtlist = NULL;
	GHashTable *db_row = NULL;

	domain_id = atoi(qvar("domain_id"));
	if (!is_domain_editable(domain_id, "domains"))
		goto out2;

	vl = add_html_var(vl, "domain_id", qvar("domain_id"));

	if (IS_SET(qvar("record_id"))) {
		record_id = atoi(qvar("record_id"));
		vl = add_html_var(vl, "record_id", qvar("record_id"));
	}

	if (IS_POST() && valid_csrf_token()) {
		ttl = atoi(qvar("dax_ttl"));
		name = make_mysql_safe_string(qvar("dax_hostname"));
		domain = make_mysql_safe_string(qvar("domain"));
		content = make_mysql_safe_string(qvar("dax_text"));

		if (ttl < 60) {
			form_err = true;
			vl = add_html_var(vl, "ttl_error", "yes");
		}
		/* Allow an empty hostname field */
		if (IS_SET(name) && !is_valid_hostname(name)) {
			form_err = true;
			vl = add_html_var(vl, "hostname_error", "yes");
		}
		if (!IS_SET(content)) {
			form_err = true;
			vl = add_html_var(vl, "content_error", "yes");
		}

		if (!form_err) {
			struct dom_rec_ent dre;

			dre.domain = domain;
			dre.name = dotchomp(name);
			dre.content = content;
			dre.type = "TXT";
			dre.prio = 0;
			dre.ttl = ttl;
			__dns_record_to_db(&dre, domain_id, record_id);

			fcgx_p("Location: /records/?domain_id=%d&type=txt#add"
					"\r\n\r\n", domain_id);
			goto out2;
		}
	}

	/* GET or unsuccessful POST */
	if (!form_err) {
		/* GET */
		char *domain;

		res = sql_query(conn, "SELECT pdns.domains.name AS domain FROM "
				"pdns.domains WHERE pdns.domains.id = %d",
				domain_id);
		db_row = get_dbrow(res);
		domain = strdupa(get_var(db_row, "domain"));
		vl = add_html_var(vl, "domain", domain);
		free_vars(db_row);
		mysql_free_result(res);

		if (!record_id) {
			vl = add_html_var(vl, "dax_ttl", "3600");
			goto out;
		}
		/* We are updating an existing record */
		res = sql_query(conn, "SELECT IF"
				"(pdns.records.name = pdns.domains.name, "
				"'', TRIM(TRAILING '.%s' FROM "
				"pdns.records.name)) AS name, "
				"pdns.records.content, "
				"pdns.records.ttl, "
				"pdns.records.prio FROM pdns.records "
				"INNER JOIN pdns.domains ON "
				"(pdns.records.domain_id = "
				"pdns.domains.id) WHERE "
				"pdns.records.domain_id = %d AND "
				"pdns.records.id = %d",
				domain, domain_id, record_id);
		db_row = get_dbrow(res);
		vl = add_html_var(vl, "dax_hostname", get_var(db_row, "name"));
		vl = add_html_var(vl, "dax_text", get_var(db_row, "content"));
		vl = add_html_var(vl, "dax_ttl", get_var(db_row, "ttl"));
		vl = add_html_var(vl, "update", "update");
		free_vars(db_row);
		mysql_free_result(res);
	} else {
		/* POST with errors */
		vl = add_html_var(vl, "domain", qvar("domain"));
		vl = add_html_var(vl, "dax_hostname", qvar("dax_hostname"));
		vl = add_html_var(vl, "dax_text", qvar("dax_text"));
		vl = add_html_var(vl, "dax_ttl", qvar("dax_ttl"));
		if (IS_SET(qvar("update")))
			vl = add_html_var(vl, "update", "update");
	}

out:
	add_csrf_token(vl);
	fmtlist = TMPL_add_fmt(fmtlist, "de_xss", de_xss);
	send_template("templates/txt_record.tmpl", vl, fmtlist);
	TMPL_free_fmtlist(fmtlist);
out2:
	TMPL_free_varlist(vl);
	free(name);
	free(domain);
	free(content);
}

/*
 * /master_ns_ip/
 *
 * HTML is in templates/master_ns_ip.tmpl
 */
static void master_ns_ip(void)
{
	int domain_id;
	char *ip = NULL;
	bool form_err = false;
	MYSQL_RES *res;
	TMPL_varlist *vl = NULL;
	TMPL_fmtlist *fmtlist = NULL;
	GHashTable *db_row = NULL;

	domain_id = atoi(qvar("domain_id"));
	if (!is_domain_editable(domain_id, "domains"))
		goto out;

	vl = add_html_var(vl, "domain_id", qvar("domain_id"));

	if (IS_POST() && valid_csrf_token()) {
		ip = make_mysql_safe_string(qvar("dax_mip"));
		if (!is_valid_ipv4_addr(ip) && !is_valid_ipv6_addr(ip)) {
			form_err = true;
			vl = add_html_var(vl, "mip_error", "yes");
		}

		if (!form_err) {
			MYSQL *sconn;
			char *domain = make_mysql_safe_string(qvar("domain"));
			const char *o_mip = qvar("o_mip");
			const char *u_sql = "UPDATE pdns.domains SET "
				"master = '%s' WHERE name = '%s' AND "
				"master = '%s'";

			sql_query(conn, u_sql, ip, domain, o_mip);

			sconn = db_conn(db_shost, "pdns", true);
			sql_query(sconn, u_sql, ip, domain, o_mip);
			mysql_close(sconn);
			free(domain);

			fcgx_p("Location: /records/?domain_id=%d&type=soa"
					"\r\n\r\n", domain_id);
			goto out;
		}
	}

	/* GET or unsuccessful POST */
	if (!form_err) {
		/* GET */
		char *domain;

		res = sql_query(conn, "SELECT name AS domain, master FROM "
				"pdns.domains WHERE domains.id = %d",
				domain_id);
		db_row = get_dbrow(res);
		domain = strdupa(get_var(db_row, "domain"));
		vl = add_html_var(vl, "domain", domain);
		vl = add_html_var(vl, "dax_mip", get_var(db_row, "master"));
		vl = add_html_var(vl, "o_mip", get_var(db_row, "master"));
		free_vars(db_row);
		mysql_free_result(res);
	} else {
		/* POST with errors */
		vl = add_html_var(vl, "domain", qvar("domain"));
		vl = add_html_var(vl, "dax_mip", qvar("dax_mip"));
		vl = add_html_var(vl, "o_mip", qvar("o_mip"));
	}

	add_csrf_token(vl);
	fmtlist = TMPL_add_fmt(fmtlist, "de_xss", de_xss);
	send_template("templates/master_ns_ip.tmpl", vl, fmtlist);
	TMPL_free_fmtlist(fmtlist);
out:
	TMPL_free_varlist(vl);
	free(ip);
}

/*
 * /entry_soa/
 *
 * HTML is in templates/entry_soa.tmpl
 */
static void entry_soa(void)
{
	int domain_id;
	MYSQL_RES *res;
	TMPL_varlist *vl = NULL;
	TMPL_fmtlist *fmtlist = NULL;
	GHashTable *db_row = NULL;
	char *soa;
	char *item;

	domain_id = atoi(qvar("domain_id"));
	if (!is_domain_editable(domain_id, "domains"))
		return;

	res = sql_query(conn, "SELECT pdns.records.name, "
			"pdns.records.content, "
			"pdns.records.ttl, "
			"pdns.domains.id AS domain_id, "
			"pdns.records.id AS record_id, "
			"pdns.domains.name AS domain, "
			"pdns.domains.type, "
			"pdns.domains.master, "
			"pdns.records.change_date, "
			"(SELECT MAX(change_date) FROM pdns.records WHERE "
			"domain_id = %d) AS serial FROM pdns.records "
			"INNER JOIN pdns.domains ON "
			"(pdns.domains.id = pdns.records.domain_id) WHERE "
			"pdns.records.domain_id = %d AND pdns.records.type = "
			"'SOA'", domain_id, domain_id);

	if (mysql_num_rows(res) == 0) {
		/*
		 * We are a slave for this domain and are waiting to do
		 * an initial AXFR. So there are no records yet.
		 */
		vl = add_html_var(vl, "axfr_done", "no");
		goto out;
	}

	db_row = get_dbrow(res);
	vl = add_html_var(vl, "domain", get_var(db_row, "domain"));
	vl = add_html_var(vl, "domain_id", get_var(db_row, "domain_id"));

	vl = add_html_var(vl, "cdate", get_var(db_row, "change_date"));
	vl = add_html_var(vl, "name", get_var(db_row, "name"));
	vl = add_html_var(vl, "type", get_var(db_row, "type"));

	soa = strdupa(get_var(db_row, "content"));
	item = strsep(&soa, " ");
	vl = add_html_var(vl, "pns", item);
	item = strsep(&soa, " ");
	vl = add_html_var(vl, "hostmaster", item);

	/*
	 * If this is a SLAVE domain, we take the serial from the
	 * SOA record. Else we use the MAX(change_date) for the
	 * domain.
	 */
	item = strsep(&soa, " ");
	if (strcmp(get_var(db_row, "type"), "SLAVE") == 0)
		vl = add_html_var(vl, "serial", item);
	else
		vl = add_html_var(vl, "serial", get_var(db_row, "serial"));

	item = strsep(&soa, " ");
	vl = add_html_var(vl, "refresh", item);
	item = strsep(&soa, " ");
	vl = add_html_var(vl, "retry", item);
	item = strsep(&soa, " ");
	vl = add_html_var(vl, "expire", item);
	item = strsep(&soa, " ");
	vl = add_html_var(vl, "ncttl", item);

	vl = add_html_var(vl, "ttl", get_var(db_row, "ttl"));
	vl = add_html_var(vl, "record_id", get_var(db_row, "record_id"));

	if (strcmp(get_var(db_row, "type"), "SLAVE") == 0)
		vl = add_html_var(vl, "mip", get_var(db_row, "master"));

	free_vars(db_row);
out:
	fmtlist = TMPL_add_fmt(fmtlist, "de_xss", de_xss);
	fmtlist = TMPL_add_fmt(fmtlist, "datetime", format_datetime_utc);
	send_template("templates/entry_soa.tmpl", vl, fmtlist);
	TMPL_free_varlist(vl);
	TMPL_free_fmtlist(fmtlist);
	mysql_free_result(res);
}

/*
 * Helper function to set the field names on the records.tmpl page.
 * Called from get_records()
 */
static TMPL_varlist *__add_record_field_names(const char *type,
					      TMPL_varlist *varlist)
{
	if (strcmp(type, "ns") == 0) {
		varlist = add_html_var(varlist, "field_a", "Domain");
		varlist = add_html_var(varlist, "field_b", "Name Server");
		varlist = add_html_var(varlist, "field_d", "TTL");
	} else if (strcmp(type, "a") == 0) {
		varlist = add_html_var(varlist, "field_a", "Hostname");
		varlist = add_html_var(varlist, "field_b", "IPv4 Address");
		varlist = add_html_var(varlist, "field_d", "TTL");
	} else if (strcmp(type, "aaaa") == 0) {
		varlist = add_html_var(varlist, "field_a", "Hostname");
		varlist = add_html_var(varlist, "field_b", "IPv6 Address");
		varlist = add_html_var(varlist, "field_d", "TTL");
	} else if (strcmp(type, "cname") == 0) {
		varlist = add_html_var(varlist, "field_a", "Alias");
		varlist = add_html_var(varlist, "field_b", "Canonical Name");
		varlist = add_html_var(varlist, "field_d", "TTL");
	} else if (strcmp(type, "loc") == 0) {
		varlist = add_html_var(varlist, "field_a", "Host");
		varlist = add_html_var(varlist, "field_b", "Location");
		varlist = add_html_var(varlist, "field_d", "TTL");
	} else if (strcmp(type, "mx") == 0) {
		varlist = add_html_var(varlist, "field_a", "Host / Domain");
		varlist = add_html_var(varlist, "field_b", "Mail Exchanger");
		varlist = add_html_var(varlist, "field_c", "Priority");
		varlist = add_html_var(varlist, "field_d", "TTL");
	} else if (strcmp(type, "naptr") == 0) {
		varlist = add_html_var(varlist, "field_a", "Host");
		varlist = add_html_var(varlist, "field_b", "NAPTR");
		varlist = add_html_var(varlist, "field_d", "TTL");
	} else if (strcmp(type, "ptr") == 0) {
		varlist = add_html_var(varlist, "field_a", "Pointer");
		varlist = add_html_var(varlist, "field_b", "Pointer To");
		varlist = add_html_var(varlist, "field_d", "TTL");
	} else if (strcmp(type, "rp") == 0) {
		varlist = add_html_var(varlist, "field_a", "Host");
		varlist = add_html_var(varlist, "field_b",
				"Responsible Person");
		varlist = add_html_var(varlist, "field_d", "TTL");
	} else if (strcmp(type, "spf") == 0) {
		varlist = add_html_var(varlist, "field_a", "Host");
		varlist = add_html_var(varlist, "field_b", "SPF");
		varlist = add_html_var(varlist, "field_d", "TTL");
	} else if (strcmp(type, "srv") == 0) {
		varlist = add_html_var(varlist, "field_a", "Service.Protocol");
		varlist = add_html_var(varlist, "field_b",
				"Weight Port Target");
		varlist = add_html_var(varlist, "field_c", "Priority");
		varlist = add_html_var(varlist, "field_d", "TTL");
	} else if (strcmp(type, "txt") == 0) {
		varlist = add_html_var(varlist, "field_a", "Host");
		varlist = add_html_var(varlist, "field_b", "Text");
		varlist = add_html_var(varlist, "field_d", "TTL");
	}

	return varlist;
}

/*
 * /records/
 *
 * HTML is in templates/records.tmpl
 */
static void get_records(const char *type)
{
	unsigned long i;
	unsigned long nr_rows;
	unsigned long nrec = 0;
	int domain_id;
	MYSQL_RES *res;
	TMPL_varlist *ml = NULL;
	TMPL_loop *record_loop = NULL;
	TMPL_fmtlist *fmtlist = NULL;
	GHashTable *db_row = NULL;
	char nr_rec[11];

	domain_id = atoi(qvar("domain_id"));
	if (!is_domain_editable(domain_id, "domains"))
		return;

	res = sql_query(conn, "SELECT pdns.records.name, "
			"pdns.records.content, "
			"pdns.records.ttl, "
			"pdns.records.prio, "
			"pdns.domains.id AS domain_id, "
			"pdns.records.id AS record_id, "
			"pdns.domains.name AS domain, "
			"pdns.domains.type, "
			"pdns.records.change_date "
			"FROM pdns.records INNER JOIN pdns.domains ON "
			"(pdns.domains.id = pdns.records.domain_id) WHERE "
			"pdns.records.domain_id = %d AND pdns.records.type = "
			"'%s' ORDER BY CAST(pdns.records.name AS UNSIGNED), "
			"pdns.records.name", domain_id, type);

	nr_rows = mysql_num_rows(res);
	if (nr_rows == 0) {
		mysql_free_result(res);
		res = sql_query(conn, "SELECT pdns.domains.name AS domain, "
				"pdns.domains.type FROM pdns.domains WHERE "
				"pdns.domains.id = %d", domain_id);
	}
	db_row = get_dbrow(res);
	ml = add_html_var(ml, "domain", get_var(db_row, "domain"));
	ml = add_html_var(ml, "stype", get_var(db_row, "type"));
	ml = add_html_var(ml, "domain_id", qvar("domain_id"));
	ml = add_html_var(ml, "type", type);
	free_vars(db_row);

	mysql_data_seek(res, 0);
	for (i = 0; i < nr_rows; i++) {
		TMPL_varlist *vl = NULL;

		db_row = get_dbrow(res);
		vl = do_zebra(vl, i);
		vl = add_html_var(vl, "name", get_var(db_row, "name"));
		vl = add_html_var(vl, "content", get_var(db_row, "content"));
		vl = add_html_var(vl, "ttl", get_var(db_row, "ttl"));
		vl = add_html_var(vl, "prio", get_var(db_row, "prio"));
		vl = add_html_var(vl, "record_id", get_var(db_row,
					"record_id"));
		vl = add_html_var(vl, "cdate", get_var(db_row, "change_date"));

		record_loop = TMPL_add_varlist(record_loop, vl);
		nrec++;
		free_vars(db_row);
	}
	if (nrec > 0)
		ml = TMPL_add_loop(ml, "records", record_loop);
	snprintf(nr_rec, sizeof(nr_rec), "%lu", nrec);
	ml = add_html_var(ml, "nr", nr_rec);

	__add_record_field_names(type, ml);

	add_csrf_token(ml);
	fmtlist = TMPL_add_fmt(fmtlist, "de_xss", de_xss);
	fmtlist = TMPL_add_fmt(fmtlist, "datetime", format_datetime_utc);
	fmtlist = TMPL_add_fmt(fmtlist, "upper", fmt_str_upper);
	send_template("templates/records.tmpl", ml, fmtlist);
	TMPL_free_varlist(ml);
	TMPL_free_fmtlist(fmtlist);
	mysql_free_result(res);
}

/*
 * /records/
 */
static void records(void)
{
	const char *type = qvar("type");

	if (strcmp(type, "ns") == 0 ||
	    strcmp(type, "a") == 0 ||
	    strcmp(type, "aaaa") == 0 ||
	    strcmp(type, "cname") == 0 ||
	    strcmp(type, "loc") == 0 ||
	    strcmp(type, "mx") == 0 ||
	    strcmp(type, "naptr") == 0 ||
	    strcmp(type, "ptr") == 0 ||
	    strcmp(type, "rp") == 0 ||
	    strcmp(type, "spf") == 0 ||
	    strcmp(type, "srv") == 0 ||
	    strcmp(type, "txt") == 0)
		get_records(type);
	else
		entry_soa();
}

/*
 * /backup_mx/
 *
 * HTML is in templates/backup_mx.tmpl
 */
static void backup_mx(void)
{
	int domain_id;
	MYSQL *mconn;
	MYSQL_RES *res;
	TMPL_varlist *vl = NULL;
	TMPL_fmtlist *fmtlist = NULL;
	GHashTable *db_row = NULL;

	domain_id = atoi(qvar("domain_id"));
	if (!is_domain_editable(domain_id, "mail_domains"))
		return;

	if (IS_SET(qvar("etrn"))) {
		if (atoi(qvar("etrn")) == 0)
			vl = add_html_var(vl, "etrn_ok", "yes");
		else
			vl = add_html_var(vl, "etrn_ok", "no");
	}

	mconn = db_conn(db_shost, "postfix", true);
	res = sql_query(mconn, "SELECT domain, queue_sz FROM relay_domains "
			"WHERE domain_id = %d", domain_id);
	db_row = get_dbrow(res);

	vl = add_html_var(vl, "domain", get_var(db_row, "domain"));
	vl = add_html_var(vl, "domain_id", qvar("domain_id"));
	vl = add_html_var(vl, "queue_sz", get_var(db_row, "queue_sz"));

	mysql_close(mconn);

	add_csrf_token(vl);
	fmtlist = TMPL_add_fmt(fmtlist, "de_xss", de_xss);
	send_template("templates/backup_mx.tmpl", vl, fmtlist);
	TMPL_free_varlist(vl);
	TMPL_free_fmtlist(fmtlist);
	mysql_free_result(res);
}

/*
 * /mail_forwarding/
 *
 * HTML is in templates/mail_forwarding.tmpl
 */
static void mail_forwarding(void)
{
	unsigned long i;
	unsigned long nr_rows;
	int domain_id;
	MYSQL_RES *res;
	TMPL_varlist *ml = NULL;
	TMPL_loop *loop = NULL;
	TMPL_fmtlist *fmtlist = NULL;
	GHashTable *db_row = NULL;

	domain_id = atoi(qvar("domain_id"));
	if (!is_domain_editable(domain_id, "mail_domains"))
		return;

	res = sql_query(conn, "SELECT postfix.local_domains.domain, "
			"postfix.forwarding.id, "
			"postfix.forwarding.source, "
			"postfix.forwarding.destination FROM "
			"postfix.local_domains INNER JOIN postfix.forwarding "
			"ON (postfix.local_domains.domain_id = "
			"postfix.forwarding.domain_id) WHERE "
			"postfix.local_domains.domain_id = %d", domain_id);
	nr_rows = mysql_num_rows(res);
	db_row = get_dbrow(res);
	ml = add_html_var(ml, "domain", get_var(db_row, "domain"));
	free_vars(db_row);
	ml = add_html_var(ml, "domain_id", qvar("domain_id"));

	mysql_data_seek(res, 0);
	for (i = 0; i < nr_rows; i++) {
		TMPL_varlist *vl = NULL;

		db_row = get_dbrow(res);
		vl = do_zebra(vl, i);
		vl = add_html_var(vl, "source", get_var(db_row, "source"));
		vl = add_html_var(vl, "destination", get_var(db_row,
					"destination"));
		vl = add_html_var(vl, "record_id", get_var(db_row, "id"));

		loop = TMPL_add_varlist(loop, vl);
		free_vars(db_row);
	}
	ml = TMPL_add_loop(ml, "records", loop);
	add_csrf_token(ml);

	fmtlist = TMPL_add_fmt(fmtlist, "de_xss", de_xss);
	send_template("templates/mail_forwarding.tmpl", ml, fmtlist);
	TMPL_free_varlist(ml);
	TMPL_free_fmtlist(fmtlist);
	mysql_free_result(res);
}

/*
 * /mail_fwd_record/
 *
 * HTML is in templates/mail_fwd_record.tmpl
 */
static void mail_fwd_record(void)
{
	int domain_id;
	int record_id = 0;
	char *src = NULL;
	char *domain = NULL;
	char *dst = NULL;
	bool form_err = false;
	MYSQL_RES *res;
	TMPL_varlist *vl = NULL;
	TMPL_fmtlist *fmtlist = NULL;
	GHashTable *db_row = NULL;

	domain_id = atoi(qvar("domain_id"));
	if (!is_domain_editable(domain_id, "mail_domains"))
		goto out2;

	vl = add_html_var(vl, "domain_id", qvar("domain_id"));

	if (IS_SET(qvar("record_id"))) {
		record_id = atoi(qvar("record_id"));
		vl = add_html_var(vl, "record_id", qvar("record_id"));
	}

	if (IS_POST() && valid_csrf_token()) {
		src = make_mysql_safe_string(qvar("dax_mfs"));
		domain = make_mysql_safe_string(qvar("domain"));
		dst = make_mysql_safe_string(qvar("dax_mfd"));

		if (IS_SET(src) && strstr(src, "@")) {
			form_err = true;
			vl = add_html_var(vl, "mfs_error", "yes");
		}
		if (!IS_SET(qvar("dax_mfd"))) {
			form_err = true;
			vl = add_html_var(vl, "mfd_error", "yes");
		}

		if (!form_err) {
			MYSQL *mconn;
			const char *o_src = qvar("o_src");
			const char *u_fwd_sql = "UPDATE postfix.forwarding SET "
				"source = '%s@%s', destination = '%s' WHERE "
				"domain_id = %d AND source = '%s'";
			const char *i_fwd_sql = "INSERT INTO "
				"postfix.forwarding "
				"(domain_id, source, destination) "
				"VALUES (%d, '%s@%s', '%s')";

			mconn = db_conn(db_shost, "postfix", true);
			if (IS_SET(qvar("update"))) {
				sql_query(conn, u_fwd_sql, src, domain, dst,
						domain_id, o_src);
				sql_query(mconn, u_fwd_sql, src, domain, dst,
						domain_id, o_src);
			} else {
				sql_query(conn, i_fwd_sql, domain_id, src,
						domain, dst);
				sql_query(mconn, i_fwd_sql, domain_id, src,
						domain, dst);
			}
			mysql_close(mconn);

			fcgx_p("Location: /mail_forwarding/?domain_id=%d"
					"\r\n\r\n", domain_id);
			goto out2;
		}
	}

	/* GET or unsuccessful POST */
	if (!form_err) {
		/* GET */
		char *domain;

		res = sql_query(conn, "SELECT domain FROM mail_domains WHERE "
				"domain_id = %d", domain_id);
		db_row = get_dbrow(res);
		domain = strdupa(get_var(db_row, "domain"));
		vl = add_html_var(vl, "domain", domain);
		free_vars(db_row);
		mysql_free_result(res);

		if (!record_id)
			goto out;
		/* We are updating an existing record */
		res = sql_query(conn, "SELECT TRIM(TRAILING '@%s' FROM source) "
				"AS name, source, destination "
				"FROM postfix.forwarding WHERE domain_id = %d "
				"AND id = %d", domain, domain_id, record_id);
		db_row = get_dbrow(res);
		vl = add_html_var(vl, "dax_mfs", get_var(db_row, "name"));
		vl = add_html_var(vl, "dax_mfd", get_var(db_row,
					"destination"));
		vl = add_html_var(vl, "o_src", get_var(db_row, "source"));
		vl = add_html_var(vl, "update", "update");
		free_vars(db_row);
		mysql_free_result(res);
	} else {
		/* POST with errors */
		vl = add_html_var(vl, "dax_mfs", qvar("dax_mfs"));
		vl = add_html_var(vl, "dax_mfd", qvar("dax_mfd"));
		vl = add_html_var(vl, "o_src", qvar("o_src"));
		vl = add_html_var(vl, "domain", qvar("domain"));
		if (IS_SET(qvar("update")))
			vl = add_html_var(vl, "update", "update");
	}

out:
	add_csrf_token(vl);
	fmtlist = TMPL_add_fmt(fmtlist, "de_xss", de_xss);
	send_template("templates/mail_fwd_record.tmpl", vl, fmtlist);
	TMPL_free_fmtlist(fmtlist);
out2:
	TMPL_free_varlist(vl);
	free(src);
	free(domain);
	free(dst);
}

static char post_buf[BUF_SIZE];
/*
 * /paypal_ipn/
 */
static void paypal_ipn(void)
{
	FILE *response;
	MYSQL_RES *res;
	CURL *curl;
	char rbuf[32] = "\0";
	const char *ti_sql = "INSERT INTO transactions (uid, txn_id, txn_st, "
		"txn_sub_st, paypal_addr, amount, direction, timestamp) "
		"VALUES (%u, '%s', '%s', %s, '%s', %g, '%s', %ld.%06ld)";
	char *txn_id;
	char *txn_st;
	char *txn_sub_st;
	char *paypal_addr;
	const char *direction;
	char url[BUF_SIZE];
	int ret;
	unsigned int uid;
	double amount;
	struct timespec tp;

	/* Is the request likely to be from PayPal? */
	if (!strstr(post_buf, "txn_id"))
		return;

	/* Check our email address to catch spoofs */
	if (strcmp(qvar("receiver_email"), PAYPAL_REC_EMAIL) != 0)
		return;

	snprintf(url, sizeof(url),
			"https://%s/cgi-bin/webscr?cmd=_notify-validate&%s",
			PAYPAL_HOST, post_buf);
	response = fmemopen(rbuf, sizeof(rbuf) - 1, "w");

	curl = curl_easy_init();
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)response);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");
	curl_easy_perform(curl);
	ret = curl_easy_perform(curl);
	if (ret != CURLE_OK)
		d_fprintf(error_log, "curl_easy_perform() failed: %s\n",
				curl_easy_strerror(ret));
	curl_easy_cleanup(curl);

	fclose(response);
	/* Send an acknowledgement */
	fcgx_p("Content-Type: text/plain\r\n\r\n");
	fcgx_p("OK\r\n");

	if (strcasestr(rbuf, "INVALID"))
		return;

	uid = strtoul(qvar("custom"), NULL, 10);
	txn_id = make_mysql_safe_string(qvar("txn_id"));
	txn_st = make_mysql_safe_string(qvar("payment_status"));
	paypal_addr = make_mysql_safe_string(qvar("payer_email"));
	amount = strtod(qvar("mc_gross"), NULL);
	if (IS_SET(qvar("pending_reason")) || IS_SET(qvar("reason_code"))) {
		char *txn_sub_st_tmp;

		if (IS_SET(qvar("pending_reason")))
			txn_sub_st_tmp = make_mysql_safe_string(qvar(
						"pending_reason"));
		else
			txn_sub_st_tmp = make_mysql_safe_string(qvar(
						"reason_code"));

		txn_sub_st = g_strdup_printf("'%s'", txn_sub_st_tmp);
		free(txn_sub_st_tmp);
	} else {
		txn_sub_st = strdup("NULL");
	}

	/* Catch duplicate messages */
	res = sql_query(conn, "SELECT id FROM transactions WHERE txn_id = "
				"'%s' AND txn_st = '%s'", txn_id, txn_st);
	if (mysql_num_rows(res) != 0)
		goto out;

	if (strcasecmp(qvar("payment_status"), "Refunded") == 0)
		direction = "OUT";
	else
		direction = "IN";
	clock_gettime(CLOCK_REALTIME, &tp);
	sql_query(conn, ti_sql, uid, txn_id, txn_st, txn_sub_st, paypal_addr,
			amount, direction, tp.tv_sec, tp.tv_nsec / NS_USEC);

	if (strcasecmp(qvar("payment_status"), "Completed") == 0)
		sql_query(conn, "UPDATE balances SET amount = amount + %g "
				"WHERE uid = %u", amount, uid);

out:
	mysql_free_result(res);
	free(txn_id);
	free(txn_st);
	free(txn_sub_st);
	free(paypal_addr);
}

/*
 * /add_funds/
 *
 * HTML is in templates/add_funds.tmpl
 */
static void add_funds(void)
{
	TMPL_varlist *vl = NULL;
	TMPL_fmtlist *fmtlist = NULL;

	if (IS_POST() && valid_csrf_token()) {
		char uid[11];
		int amount = atoi(qvar("dax_amount"));
		bool form_err = false;

		if (amount < 5 || amount % 5 > 0) {
			form_err = true;
			vl = add_html_var(vl, "amount_error", "yes");
		} else {
			vl = add_html_var(vl, "amount_error", "no");
		}

		if (form_err) {
			vl = add_html_var(vl, "dax_amount", qvar("dax_amount"));
		} else {
			char amnt[11];

			snprintf(amnt, sizeof(amnt), "%d.00", amount);
			vl = add_html_var(vl, "dax_amount", amnt);
		}
		snprintf(uid, sizeof(uid), "%u", user_session.uid);
		vl = add_html_var(vl, "uid", uid);
		vl = add_html_var(vl, "paypal_bid", PAYPAL_BID);
	}
	vl = add_html_var(vl, "paypal_host", PAYPAL_HOST);
	vl = add_html_var(vl, "app_host", APP_HOST);

	vl = add_csrf_token(vl);
	fmtlist = TMPL_add_fmt(fmtlist, "de_xss", de_xss);
	send_template("templates/add_funds.tmpl", vl, fmtlist);
	TMPL_free_varlist(vl);
	TMPL_free_fmtlist(fmtlist);
}

/*
 * /renew/
 *
 * HTML is in templates/renew.tmpl
 */
static void renew(void)
{
	int domain_id;
	MYSQL_RES *res;
	TMPL_varlist *vl = NULL;
        TMPL_fmtlist *fmtlist = NULL;
	const char *ti_sql = "INSERT INTO transactions (uid, txn_st, amount, "
		"direction, note, timestamp) VALUES (%u, 'Completed', %g, "
		"'OUT', '%s', %ld.%06ld)";
	const char *dtable;
	char *domain;
	char f_remain[10];
	char funds[10];
	char nexpire[11];
	double amount;
	time_t n_expires;
	GHashTable *db_row = NULL;

	if (strcmp(qvar("type"), "dns") == 0)
		dtable = "domains";
	else if (strcmp(qvar("type"), "mail") == 0)
		dtable = "mail_domains";
	else
		return;

	domain_id = atoi(qvar("domain_id"));
	if (!is_users_domain(domain_id, dtable))
		return;

	if (strcmp(qvar("type"), "dns") == 0)
		res = sql_query(conn, "SELECT balances.amount, "
				"pdns.domains.name AS domain, "
				"pdns.domains.type AS dtype, "
				"domains.expires, domains.expired FROM "
				"balances INNER JOIN domains ON "
				"(domains.uid = balances.uid) INNER JOIN "
				"pdns.domains ON (pdns.domains.id = "
				"domains.domain_id) WHERE domains.domain_id "
				"= %d", domain_id);
	else
		res = sql_query(conn, "SELECT balances.amount, "
				"mail_domains.domain, mail_domains.type, "
				"mail_domains.expires, mail_domains.expired "
				"FROM balances INNER JOIN mail_domains ON "
				"(balances.uid = mail_domains.uid) WHERE "
				"mail_domains.domain_id = %d", domain_id);
	db_row = get_dbrow(res);
	amount = strtod(get_var(db_row, "amount"), NULL);

	/*
	 * If the domain hasn't expired then the new expiry date is
	 * set from the expires date. If it has, it's set from now.
	 */
	if (strcmp(get_var(db_row, "expired"), "0") == 0) {
		time_t expires = atol(get_var(db_row, "expires"));
		n_expires = expires + 86400 * 365;
	} else {
		n_expires = time(NULL) + 86400 * 365;
	}

	domain = make_mysql_safe_string(get_var(db_row, "domain"));
	mysql_free_result(res);

	snprintf(funds, sizeof(funds), "%g.00", amount);
	if (strcmp(qvar("type"), "dns") == 0)
		amount -= 10.0;
	else
		amount -= 15.0;

	if (amount < 0.0)
		vl = add_html_var(vl, "efunds", "yes");
	snprintf(f_remain, sizeof(f_remain), "%g.00", amount);
	snprintf(nexpire, sizeof(nexpire), "%ld", n_expires);

	vl = add_html_var(vl, "type", qvar("type"));
	vl = add_html_var(vl, "domain", get_var(db_row, "domain"));
	vl = add_html_var(vl, "domain_id", qvar("domain_id"));
	vl = add_html_var(vl, "funds", funds);
	vl = add_html_var(vl, "f_remain", f_remain);
	vl = add_html_var(vl, "n_expires", nexpire);
	/* For the authentication */
	vl = add_html_var(vl, "username", user_session.username);

	if (IS_POST() && valid_csrf_token()) {
		int ret;

		ret = check_auth();
		if (ret == 0) {
			double amnt;
			const char *type;
			const char *m_type;
			char note[256];
			struct timespec tp;
			int expired;

			if (strcmp(qvar("type"), "dns") == 0) {
				amnt = 10.0;
				type = "DNS";
			} else {
				amnt = 15.0;
				type = "Mail";
			}
			snprintf(note, sizeof(note), "Renewal of %s domain %s",
					type, get_var(db_row, "domain"));
			clock_gettime(CLOCK_REALTIME, &tp);

			sql_query(conn, "UPDATE %s SET expires = %ld, expired "
					"= 0, notified = 0 WHERE uid = %u AND "
					"domain_id = %d", dtable, n_expires,
					user_session.uid, domain_id);

			sql_query(conn, ti_sql, user_session.uid, amnt, note,
					tp.tv_sec, tp.tv_nsec / NS_USEC);

			sql_query(conn, "UPDATE balances SET amount = %g "
					"WHERE uid = %u",
					amount, user_session.uid);

			/* Re-enable disabled domain functionality */
			expired = atoi(get_var(db_row, "expired"));
			m_type = get_var(db_row, "type");
			if (expired && strcmp(qvar("type"), "dns") == 0) {
				const char *r_sql = "UPDATE pdns.records SET "
					"name = SUBSTRING(name FROM 3) WHERE "
					"domain_id = %d";
				const char *d_type = get_var(db_row, "dtype");
				MYSQL *sconn;

				sql_query(conn, r_sql, domain_id);
				sconn = db_conn(db_shost, "pdns", true);
				sql_query(sconn, r_sql, domain_id);
				if (strcmp(d_type, "SLAVE") == 0) {
					const char *s_sql = "UPDATE "
						"pdns.domains SET master = "
						"SUBSTRING(master FROM 3) "
						"WHERE id = %d";

					sql_query(conn, s_sql, domain_id);
					sql_query(sconn, s_sql, domain_id);
				}
				mysql_close(sconn);
			} else if (expired && strcmp(m_type, "MX") == 0) {
				MYSQL *sconn;

				sconn = db_conn(db_shost, "pdns", true);
				sql_query(sconn, "UPDATE postfix.relay_domains "					"SET enabled = 1 WHERE domain_id = %d",
					domain_id);
				mysql_close(sconn);
			} else if (expired && strcmp(m_type, "FWD") == 0) {
				const char *u_sql = "UPDATE "
					"postfix.local_domains SET enabled = 1 "					"WHERE domain_id = %d";
				MYSQL *sconn;

				sql_query(conn, u_sql, domain_id);
				sconn = db_conn(db_shost, "postfix", true);
				sql_query(sconn, u_sql, domain_id);
				mysql_close(sconn);
			}

			fcgx_p("Location: /overview/\r\n\r\n");
			goto out;
		} else {
			vl = add_html_var(vl, "auth_err", "yes");
		}
	}

	vl = add_csrf_token(vl);
	fmtlist = TMPL_add_fmt(fmtlist, "de_xss", de_xss);
	fmtlist = TMPL_add_fmt(fmtlist, "date", format_date_utc);
	send_template("templates/renew.tmpl", vl, fmtlist);
	TMPL_free_varlist(vl);
	TMPL_free_fmtlist(fmtlist);
out:
	free(domain);
}

/*
 * /transactions/
 *
 * HTML is in templates/transcations.tmpl
 */
static void transactions(void)
{
	unsigned long i;
	unsigned long nr_rows;
	TMPL_varlist *ml = NULL;
	TMPL_loop *loop = NULL;
	TMPL_fmtlist *fmtlist = NULL;
	MYSQL_RES *res;

	res = sql_query(conn, "SELECT txn_st, txn_sub_st, amount, direction, "
			"note, timestamp FROM transactions WHERE uid = %u "
			"ORDER BY timestamp DESC", user_session.uid);

	nr_rows = mysql_num_rows(res);
	for (i = 0; i < nr_rows; i++) {
		GHashTable *db_row = NULL;
		TMPL_varlist *vl = NULL;
		const char *txn_st;
		const char *direction;

		db_row = get_dbrow(res);
		vl = do_zebra(vl, i);
		vl = add_html_var(vl, "amount", get_var(db_row, "amount"));
		vl = add_html_var(vl, "status", get_var(db_row, "txn_st"));
		vl = add_html_var(vl, "reason", get_var(db_row, "txn_sub_st"));
		vl = add_html_var(vl, "note", get_var(db_row, "note"));
		vl = add_html_var(vl, "datetime", get_var(db_row,
					"timestamp"));

		txn_st = get_var(db_row, "txn_st");
		direction = get_var(db_row, "direction");
		if (strcasecmp(txn_st, "Completed") == 0 &&
		    strcasecmp(direction, "IN") == 0)
			vl = add_html_var(vl, "t_stat", "IN");
		else if (strcasecmp(txn_st, "Completed") == 0 &&
		         strcasecmp(direction, "OUT") == 0)
			vl = add_html_var(vl, "t_stat", "OUT");
		else
			vl = add_html_var(vl, "t_stat", "error");

		loop = TMPL_add_varlist(loop, vl);
		free_vars(db_row);
	}
	ml = TMPL_add_loop(ml, "transactions", loop);

	fmtlist = TMPL_add_fmt(fmtlist, "de_xss", de_xss);
	fmtlist = TMPL_add_fmt(fmtlist, "datetime", format_datetime_utc);
	send_template("templates/transactions.tmpl", ml, fmtlist);
	TMPL_free_varlist(ml);
	TMPL_free_fmtlist(fmtlist);
	mysql_free_result(res);
}

/*
 * /overview/
 *
 * HTML is in templates/overview.tmpl
 */
static void overview(void)
{
	unsigned long i;
	unsigned long nr_rows;
	MYSQL_RES *res;
	MYSQL_ROW row;
	TMPL_varlist *ml = NULL;
	TMPL_loop *loop = NULL;
	TMPL_fmtlist *fmtlist = NULL;
	char nr_rec[11];

	res = sql_query(conn, "SELECT amount FROM balances WHERE uid = %u",
			user_session.uid);
	row = mysql_fetch_row(res);
	ml = add_html_var(ml, "funds", row[0]);

	/* DNS domains */
	mysql_free_result(res);
	res = sql_query(conn, "SELECT pdns.domains.name AS domain, "
			"dnsandmx_admin.domains.expires, "
			"dnsandmx_admin.domains.expired, "
			"dnsandmx_admin.domains.added, "
			"pdns.domains.last_check, "
			"pdns.domains.type, "
			"pdns.domains.id FROM "
			"pdns.domains INNER JOIN dnsandmx_admin.domains ON "
			"(pdns.domains.id = dnsandmx_admin.domains.domain_id) "
			"WHERE dnsandmx_admin.domains.uid = %u ORDER BY "
			"type, name", user_session.uid);
	nr_rows = mysql_num_rows(res);

	for (i = 0; i < nr_rows; i++) {
		time_t tadded;
		time_t texpires;
		time_t tdiff;
		time_t tnow = time(NULL);
		int expired;
		GHashTable *db_row = NULL;
		TMPL_varlist *vl = NULL;

		db_row = get_dbrow(res);
		vl = do_zebra(vl, i);
		vl = add_html_var(vl, "domain", get_var(db_row, "domain"));
		if (strcmp(get_var(db_row, "type"), "MASTER") == 0) {
			vl = add_html_var(vl, "type", "Primary");
		} else if (strcmp(get_var(db_row, "type"), "SLAVE") == 0) {
			vl = add_html_var(vl, "type", "Secondary");
			vl = add_html_var(vl, "last_check", get_var(db_row,
						"last_check"));
		}

		vl = add_html_var(vl, "added", get_var(db_row, "added"));
		vl = add_html_var(vl, "expires", get_var(db_row, "expires"));
		vl = add_html_var(vl, "domain_id", get_var(db_row, "id"));

		tadded = atol(get_var(db_row, "added"));
		texpires = atol(get_var(db_row, "expires"));
		tdiff = texpires - tadded;
		expired = atoi(get_var(db_row, "expired"));

		if (expired) {
			vl = add_html_var(vl, "exp", "expired");
		} else if (tdiff <= 86400 * 30) {
			 if (texpires - tnow <= 86400 * 14)
				vl = add_html_var(vl, "exp", "warn");
		} else if (texpires - tnow <= 86400 * 30) {
			vl = add_html_var(vl, "exp", "warn");
		}

		loop = TMPL_add_varlist(loop, vl);
		free_vars(db_row);
	}
	ml = TMPL_add_loop(ml, "dns", loop);
	snprintf(nr_rec, sizeof(nr_rec), "%lu", i);
	ml = add_html_var(ml, "nr_dns", nr_rec);

	/* Mail domains */
	mysql_free_result(res);
	res = sql_query(conn, "SELECT mail_domains.domain_id AS id, "
			"mail_domains.domain, mail_domains.expires, "
			"mail_domains.expired, mail_domains.added, "
			"mail_domains.type FROM mail_domains WHERE "
			"mail_domains.uid = %u ORDER BY type, domain",
			user_session.uid);
	nr_rows = mysql_num_rows(res);

	loop = NULL;
	for (i = 0; i < nr_rows; i++) {
		time_t tadded;
		time_t texpires;
		time_t tdiff;
		time_t tnow = time(NULL);
		int expired;
		GHashTable *db_row = NULL;
		TMPL_varlist *vl = NULL;

		db_row = get_dbrow(res);
		vl = do_zebra(vl, i);
		vl = add_html_var(vl, "domain", get_var(db_row, "domain"));
		vl = add_html_var(vl, "type", get_var(db_row, "type"));
		vl = add_html_var(vl, "added", get_var(db_row, "added"));
		vl = add_html_var(vl, "expires", get_var(db_row, "expires"));
		vl = add_html_var(vl, "domain_id", get_var(db_row, "id"));

		tadded = atol(get_var(db_row, "added"));
		texpires = atol(get_var(db_row, "expires"));
		tdiff = texpires - tadded;
		expired = atoi(get_var(db_row, "expired"));

		if (expired) {
			vl = add_html_var(vl, "exp", "expired");
		} else if (tdiff <= 86400 * 30) {
			 if (texpires - tnow <= 86400 * 14)
				vl = add_html_var(vl, "exp", "warn");
		} else if (texpires - tnow <= 86400 * 30) {
			vl = add_html_var(vl, "exp", "warn");
		}

		loop = TMPL_add_varlist(loop, vl);
		free_vars(db_row);
	}
	ml = TMPL_add_loop(ml, "mail", loop);
	snprintf(nr_rec, sizeof(nr_rec), "%lu", i);
	ml = add_html_var(ml, "nr_mail", nr_rec);

	ml = add_html_var(ml, "www_host", WWW_HOST);
	fmtlist = TMPL_add_fmt(fmtlist, "de_xss", de_xss);
	fmtlist = TMPL_add_fmt(fmtlist, "date", format_date_utc);
	fmtlist = TMPL_add_fmt(fmtlist, "datetime", format_datetime_utc);
	send_template("templates/overview.tmpl", ml, fmtlist);
	TMPL_free_varlist(ml);
	TMPL_free_fmtlist(fmtlist);
	mysql_free_result(res);
}

/*
 * /sign_up/
 *
 * HTML is in templates/sign_up.tmpl
 */
static void sign_up(void)
{
	char *email;
	char *email_addr;
	char key[SHA1_LEN + 1];
	TMPL_fmtlist *fmtlist = NULL;
	TMPL_varlist *vl = NULL;

	if (!IS_POST())
		return;

	email_addr = (char *)qvar("email_addr");
	email_addr = g_strstrip(email_addr);

	if (!IS_SET(email_addr)) {
		vl = add_html_var(vl, "no_email", "yes");
		goto out;
	}

	if (!is_valid_email_address(email_addr)) {
		vl = add_html_var(vl, "invalid_email", "yes");
		goto out;
	}

	if (user_already_exists(email_addr)) {
		vl = add_html_var(vl, "user_exists", "yes");
		goto out;
	}

	email = make_mysql_safe_string(email_addr);
	generate_hash(key, SHA1);
	sql_query(conn, "REPLACE INTO pending_activations VALUES "
			"('%s', '%s', %ld)", email, key, time(NULL) + 86400);
	send_activation_mail(email_addr, key);
	free(email);

out:
	vl = add_html_var(vl, "email_addr", email_addr);
	vl = add_html_var(vl, "www_host", WWW_HOST);

	fmtlist = TMPL_add_fmt(fmtlist, "de_xss", de_xss);
	send_template("templates/sign_up.tmpl", vl, fmtlist);
	TMPL_free_varlist(vl);
	TMPL_free_fmtlist(fmtlist);
}

/*
 * /activate_account/
 *
 * HTML is in templates/activate_account.tmpl
 */
static void activate_account(void)
{
	bool form_err = false;
	char *name = NULL;
	char *key = NULL;
	MYSQL_RES *res;
	MYSQL_ROW row;
	TMPL_varlist *vl = NULL;
	TMPL_fmtlist *fmtlist = NULL;

	if (IS_POST()) {
		name = make_mysql_safe_string(qvar("dax_name"));
		key = make_mysql_safe_string(qvar("key"));

		if (!IS_SET(qvar("dax_name"))) {
			vl = add_html_var(vl, "name_error", "yes");
			form_err = true;
		} else {
			vl = add_html_var(vl, "dax_name", qvar("dax_name"));
		}

		if (strlen(qvar("dax_pass1")) > 7 &&
		    strlen(qvar("dax_pass2")) > 7) {
			if (strcmp(qvar("dax_pass1"), qvar("dax_pass2")) != 0) {
				vl = add_html_var(vl, "pass_error", "mismatch");
				form_err = true;
			}
		} else {
			vl = add_html_var(vl, "pass_error", "length");
			form_err = true;
		}

		if (!form_err) {
			unsigned int uid;
			char *password;
			char *email;

			res = sql_query(conn, "SELECT email FROM "
					"pending_activations WHERE akey = "
					"'%s'", key);
			if (!mysql_num_rows(res))
				goto out;
			row = mysql_fetch_row(res);
			email = make_mysql_safe_string(row[0]);
			mysql_free_result(res);

			/* We need to be sure a new uid isn't inserted here */
			sql_query(conn, "LOCK TABLES passwd WRITE");
			res = sql_query(conn, "SELECT IF(MAX(uid) < 1000 OR "
					"MAX(uid) IS NULL, 1000, "
					"MAX(uid) + 1) FROM passwd");
			row = mysql_fetch_row(res);
			uid = strtoul(row[0], NULL, 10);
			mysql_free_result(res);

			password = generate_password_hash(SHA512,
					qvar("dax_pass1"));

			sql_query(conn, "INSERT INTO passwd VALUES "
					"(%u, %u, '%s', '%s', '%s', 0, 1, '', "
					"%ld)", uid, uid, email, password,
					name, time(NULL));
			sql_query(conn, "UNLOCK TABLES");
			sql_query(conn, "INSERT INTO balances (uid, amount)"
					"VALUES (%u, 0.0)", uid);
			sql_query(conn, "INSERT INTO ipacl (uid, enabled, "
					"list) VALUES (%u, 0, '')", uid);
			sql_query(conn, "DELETE FROM pending_activations "
					"WHERE akey = '%s'", key);

			fcgx_p("Location: /activate_account/?activated=yes"
					"\r\n\r\n");
			free(email);
			goto out;
		}
	}

	if (IS_SET(qvar("activated"))) {
		vl = add_html_var(vl, "activated", "yes");
	} else {
		res = sql_query(conn, "SELECT email FROM pending_activations "
				"WHERE akey = '%s'", qvar("key"));
		if (!mysql_num_rows(res)) {
			vl = add_html_var(vl, "no_key", "yes");
			form_err = true;
		} else {
			row = mysql_fetch_row(res);
			vl = add_html_var(vl, "email_addr", row[0]);
		}
		mysql_free_result(res);
	}
	vl = add_html_var(vl, "key", qvar("key"));
	vl = add_html_var(vl, "www_host", WWW_HOST);

	fmtlist = TMPL_add_fmt(fmtlist, "de_xss", de_xss);
	send_template("templates/activate_account.tmpl", vl, fmtlist);
	TMPL_free_fmtlist(fmtlist);
out:
	TMPL_free_varlist(vl);
	free(name);
	free(key);
}

/*
 * /reset_password/
 *
 * HTML is in templates/reset_password.tmpl
 */
static void reset_password(void)
{
	bool form_err = false;
	char *email = NULL;
	MYSQL_RES *res;
	MYSQL_ROW row;
	TMPL_varlist *vl = NULL;
	TMPL_fmtlist *fmtlist = NULL;

	if (IS_POST() && IS_SET(qvar("send_email"))) {
		if (!user_already_exists(qvar("email_addr"))) {
			vl = add_html_var(vl, "email", qvar("email_addr"));
			vl = add_html_var(vl, "no_user", "yes");
		} else {
			char key[SHA1_LEN + 1];

			email = make_mysql_safe_string(qvar("email_addr"));
			generate_hash(key, SHA1);
			sql_query(conn, "REPLACE INTO pending_activations "
					"VALUES ('%s', '%s', %ld)", email, key,
					time(NULL) + 86400);
			send_reset_password_mail(qvar("email_addr"), key);
			vl = add_html_var(vl, "email_sent", "yes");
			vl = add_html_var(vl, "email", qvar("email_addr"));
		}
	} else if (IS_POST() && IS_SET(qvar("reset_password"))) {
		vl = add_html_var(vl, "valid_key", "yes");
		vl = add_html_var(vl, "key", qvar("key"));
		vl = add_html_var(vl, "email_addr", qvar("email_addr"));

		if (strlen(qvar("dax_pass1")) > 7 &&
		    strlen(qvar("dax_pass2")) > 7) {
			if (strcmp(qvar("dax_pass1"), qvar("dax_pass2")) != 0) {
				vl = add_html_var(vl, "pass_error", "mismatch");
				form_err = true;
			}
		} else {
			vl = add_html_var(vl, "pass_error", "length");
			form_err = true;
		}

		if (!form_err) {
			char *password;
			char *key;

			key = make_mysql_safe_string(qvar("key"));
			res = sql_query(conn, "SELECT email FROM "
					"pending_activations WHERE akey = "
					"'%s'", key);
			if (!mysql_num_rows(res))
				goto out;
			row = mysql_fetch_row(res);
			email = make_mysql_safe_string(row[0]);
			mysql_free_result(res);

			password = generate_password_hash(SHA512,
					qvar("dax_pass1"));

			sql_query(conn, "UPDATE passwd SET password = '%s' "
					"WHERE username = '%s'", password,
					email);
			sql_query(conn, "DELETE FROM pending_activations "
					"WHERE akey = '%s'", key);
			free(key);

			vl = add_html_var(vl, "reset", "yes");
		}
	}

	if (IS_GET() && IS_SET(qvar("reset"))) {
		vl = add_html_var(vl, "reset", "yes");
	} else if (IS_GET() && IS_SET(qvar("key"))) {
		res = sql_query(conn, "SELECT email FROM pending_activations "
				"WHERE akey = '%s'", qvar("key"));
		if (!mysql_num_rows(res)) {
			vl = add_html_var(vl, "valid_key", "no");
		} else {
			row = mysql_fetch_row(res);
			vl = add_html_var(vl, "email_addr", row[0]);
			vl = add_html_var(vl, "key", qvar("key"));
			vl = add_html_var(vl, "valid_key", "yes");
		}
		mysql_free_result(res);
	}

	fmtlist = TMPL_add_fmt(fmtlist, "de_xss", de_xss);
	send_template("templates/reset_password.tmpl", vl, fmtlist);
	TMPL_free_fmtlist(fmtlist);
out:
	TMPL_free_varlist(vl);
	free(email);
}

/*
 * /disable_ipacl/
 *
 * HTML is in templates/disable_ipacl.tmpl
 */
static void disable_ipacl(void)
{
	TMPL_varlist *vl = NULL;
	TMPL_fmtlist *fmtlist = NULL;

	if (IS_POST() && IS_SET(qvar("send_email"))) {
		if (!user_already_exists(qvar("email_addr"))) {
			vl = add_html_var(vl, "email", qvar("email_addr"));
			vl = add_html_var(vl, "no_user", "yes");
		} else {
			char key[SHA1_LEN + 1];
			char *email = NULL;

			email = make_mysql_safe_string(qvar("email_addr"));
			generate_hash(key, SHA1);
			sql_query(conn, "REPLACE INTO pending_ipacl_deact "
					"VALUES ('%s', '%s', %ld)", email, key,
					time(NULL) + 86400);
			send_disable_ipacl_mail(qvar("email_addr"), key);
			vl = add_html_var(vl, "email_sent", "yes");
			vl = add_html_var(vl, "email", qvar("email_addr"));
			free(email);
		}
	} else if (IS_GET() && IS_SET(qvar("key"))) {
		MYSQL_RES *res;

		res = sql_query(conn, "SELECT email, passwd.uid FROM "
				"pending_ipacl_deact, passwd WHERE "
				"pending_ipacl_deact.dkey = '%s' AND "
				"passwd.username = pending_ipacl_deact.email",
				qvar("key"));
		if (!mysql_num_rows(res)) {
			vl = add_html_var(vl, "valid_key", "no");
		} else {
			char *key = make_mysql_safe_string(qvar("key"));
			MYSQL_ROW row = mysql_fetch_row(res);
			unsigned int uid = strtoul(row[1], NULL, 10);

			sql_query(conn, "UPDATE ipacl SET enabled = 0 WHERE "
					"uid = %u", uid);
			sql_query(conn, "DELETE FROM pending_ipacl_deact "
					"WHERE dkey = '%s'", key);
			free(key);

			vl = add_html_var(vl, "email_addr", row[0]);
			vl = add_html_var(vl, "valid_key", "yes");
		}
		mysql_free_result(res);
	}

	fmtlist = TMPL_add_fmt(fmtlist, "de_xss", de_xss);
	send_template("templates/disable_ipacl.tmpl", vl, fmtlist);
	TMPL_free_fmtlist(fmtlist);
	TMPL_free_varlist(vl);
}

static void tools(void)
{
	unsigned long nr_rows;
	unsigned long i;
	MYSQL_RES *res;
	TMPL_varlist *ml = NULL;
	TMPL_loop *domains = NULL;
	TMPL_loop *mail_fwd = NULL;
	TMPL_fmtlist *fmtlist = NULL;

	if (IS_GET() && IS_SET(env_vars.query_string)) {
		int domain_id = atoi(qvar("domain"));

		if (domain_id == -1 || strcmp(qvar("format"), "-1") == 0) {
			fcgx_p("Location: /tools/\r\n\r\n");
			return;
		}
		if (IS_SET(qvar("extract_dns"))) {
			if (strcmp(qvar("format"), "bind") == 0)
				dump_dns_domain_to_bind(domain_id);
			else if (strcmp(qvar("format"), "csv") == 0)
				dump_dns_domain_to_csv(domain_id);
		} else if (IS_SET(qvar("extract_mail_fwd"))) {
			if (strcmp(qvar("format"), "csv") == 0)
				dump_mail_fwd_to_csv(domain_id);
		}
		return;
	}

	/* Get A list of DNS domains */
	res = sql_query(conn, "SELECT domain_id, name FROM domains INNER JOIN "
			"pdns.domains ON (domains.domain_id = "
			"pdns.domains.id) WHERE uid = %u ORDER BY name",
			user_session.uid);

	nr_rows = mysql_num_rows(res);
	for (i = 0; i < nr_rows; i++) {
		TMPL_varlist *vl = NULL;
		GHashTable *db_row = NULL;

		db_row = get_dbrow(res);
		vl = add_html_var(vl, "id", get_var(db_row, "domain_id"));
		vl = add_html_var(vl, "domain", get_var(db_row, "name"));

		domains = TMPL_add_varlist(domains, vl);
		free_vars(db_row);
	}
	ml = TMPL_add_loop(ml, "domains", domains);
	mysql_free_result(res);

	/* Get a list mail forwarding domains */
	res = sql_query(conn, "SELECT domain_id, domain FROM mail_domains "
			"WHERE uid = %u AND type = 'FWD' ORDER BY domain",
			user_session.uid);

	nr_rows = mysql_num_rows(res);
	for (i = 0; i < nr_rows; i++) {
		TMPL_varlist *vl = NULL;
		GHashTable *db_row = NULL;

		db_row = get_dbrow(res);
		vl = add_html_var(vl, "id", get_var(db_row, "domain_id"));
		vl = add_html_var(vl, "domain", get_var(db_row, "domain"));

		mail_fwd = TMPL_add_varlist(mail_fwd, vl);
		free_vars(db_row);
	}
	ml = TMPL_add_loop(ml, "mail_fwd", mail_fwd);
	mysql_free_result(res);

	fmtlist = TMPL_add_fmt(fmtlist, "de_xss", de_xss);
	send_template("templates/tools.tmpl", ml, fmtlist);
	TMPL_free_fmtlist(fmtlist);
	TMPL_free_varlist(ml);
}

/*
 * /ips_and_hosts/
 *
 * HTML is in templates/ips_and_hosts.tmpl
 */
static void ips_and_hosts(void)
{
	TMPL_varlist *vl = NULL;
	TMPL_fmtlist *fmtlist = NULL;

	vl = add_html_var(vl, "www_host", WWW_HOST);
	fmtlist = TMPL_add_fmt(fmtlist, "de_xss", de_xss);
	send_template("templates/ips_and_hosts.tmpl", vl, fmtlist);
	TMPL_free_fmtlist(fmtlist);
	TMPL_free_varlist(vl);
}

static char *request_uri;
/*
 * Given a URI we are checking for against request_uri
 * Return:
 *     true for a match and
 *     false for no match.
 */
static bool match_uri(const char *uri)
{
	size_t rlen;
	size_t mlen = strlen(uri);
	const char *request;
	char *req = strdupa(request_uri);

	/*
	 * Handle URLs in the form /something/?key=value by stripping
	 * everything from the ? onwards and matching on the initial part.
	 */
	if (strchr(request_uri, '?'))
		request = strtok(req, "?");
	else
		request = request_uri;

	rlen = strlen(request);

	if (strncmp(request, uri, mlen) == 0 && rlen == mlen)
		return true;
	else
		return false;
}

static jmp_buf env;
/*
 * This is the main URI mapping/routing function.
 *
 * Takes a URI string to match and the function to run if it matches
 * request_uri.
 */
static inline void uri_map(const char *uri, void (uri_handler)(void))
{
	if (match_uri(uri)) {
		uri_handler();
		longjmp(env, 1);
	}
}

/*
 * Main application. This is where the requests come in and routed.
 */
void handle_request(void)
{
	bool logged_in = false;
	struct timespec stp;
	struct timespec etp;

	clock_gettime(CLOCK_REALTIME, &stp);

	qvars = NULL;
	avars = NULL;
	u_files = NULL;
	user_session.name = NULL;

	set_env_vars();
	request_uri = strdupa(env_vars.request_uri);
	/*
	 * If we get POST data, we need to make a copy of it incase it is
	 * from PayPal's IPN service. We need to acquire the post buffer
	 * here otherwise it will be eaten in set_vars() and won't be
	 * available for paypal_ipn() which requires us to send back the
	 * post data exactly as we received it for verification.
	 */
	if (strstr(env_vars.content_type, "x-www-form-urlencoded")) {
		memset(post_buf, 0, sizeof(post_buf));
		fcgx_gs(post_buf, sizeof(post_buf) - 1);
	}
	set_vars(post_buf);

	/* Initialise the database connection for the master name server */
	conn = db_conn(db_host, db_name, false);
	if (!conn)
		goto out2;

	/* Return from non-authenticated URIs and goto 'out2' */
	if (setjmp(env))
		goto out2;

	/*
	 * Some routes need to come before the login / session stuff as
	 * they can't be logged in and have no session.
	 */
	uri_map("/paypal_ipn/", paypal_ipn);
	uri_map("/sign_up/", sign_up);
	uri_map("/activate_account/", activate_account);
	uri_map("/reset_password/", reset_password);
	uri_map("/disable_ipacl/", disable_ipacl);
	uri_map("/login/", login);

	logged_in = is_logged_in();
	if (!logged_in) {
		fcgx_p("Location: /login/\r\n\r\n");
		goto out2;
	}

	/* Logged in, set-up the user_session structure */
	set_user_session();

	/* Return from authenticated URIs and goto 'out' */
	if (setjmp(env))
		goto out;

	/* Add new url handlers after here */
	uri_map("/overview/", overview);
	uri_map("/settings/", settings);
	uri_map("/transactions/", transactions);
	uri_map("/records/", records);
	uri_map("/soa_record/", soa_record);
	uri_map("/master_ns_ip/", master_ns_ip);
	uri_map("/ns_record/", ns_record);
	uri_map("/a_record/", a_record);
	uri_map("/aaaa_record/", aaaa_record);
	uri_map("/cname_record/", cname_record);
	uri_map("/loc_record/", loc_record);
	uri_map("/mx_record/", mx_record);
	uri_map("/naptr_record/", naptr_record);
	uri_map("/ptr_record/", ptr_record);
	uri_map("/rp_record/", rp_record);
	uri_map("/spf_record/", spf_record);
	uri_map("/srv_record/", srv_record);
	uri_map("/txt_record/", txt_record);
	uri_map("/delete_dns_record/", delete_dns_record);
	uri_map("/delete_dns_domain/", delete_dns_domain);
	uri_map("/delete_mail_domain/", delete_mail_domain);
	uri_map("/delete_mail_fwd_record/", delete_mail_fwd_record);
	uri_map("/add_dns_domain/", add_dns_domain);
	uri_map("/add_mail_domain/", add_mail_domain);
	uri_map("/mail_forwarding/", mail_forwarding);
	uri_map("/mail_fwd_record/", mail_fwd_record);
	uri_map("/backup_mx/", backup_mx);
	uri_map("/issue_etrn/", issue_etrn);
	uri_map("/add_funds/", add_funds);
	uri_map("/renew/", renew);
	uri_map("/ips_and_hosts/", ips_and_hosts);
	uri_map("/tools/", tools);
	uri_map("/logout/", logout);

	/* Default location */
	fcgx_p("Location: /login/\r\n\r\n");

out:
	free_user_session();

out2:
	free_vars(qvars);
	free_avars();
	free_u_files();
	clock_gettime(CLOCK_REALTIME, &etp);
	d_fprintf(access_log, "%s %s (%s), %ums\n",
				env_vars.remote_addr,
				request_uri,
				env_vars.request_method,
				(unsigned int)((etp.tv_sec * 1000 +
				etp.tv_nsec / NS_MSEC) -
				(stp.tv_sec * 1000 + stp.tv_nsec / NS_MSEC)));
	free_env_vars();
	mysql_close(conn);
}
