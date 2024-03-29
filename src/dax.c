/*
 * dax.c - Main application core
 *
 * Copyright (C) 2012 - 2013	OpenTech Labs
 *				Andrew Clayton <andrew@digital-domain.net>
 *		 2013 - 2014	DNSandMX
 *				Andrew Clayton <andrew@dnsandmx.com>
 *
 * Licensed under the GNU Affero General Public License version 3
 * See AGPL-3.0.txt
 */

#define _GNU_SOURCE	1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <limits.h>
#include <sys/sysinfo.h>

#include <fcgiapp.h>

#include "common.h"
#include "url_handlers.h"
#include "utils.h"
#include "dax.h"

extern char **environ;
static char **rargv;

static volatile sig_atomic_t create_nr_new_server;
static volatile sig_atomic_t dump_sessions;
static volatile sig_atomic_t housekeeping;
static volatile sig_atomic_t rotate_log_files;

static char access_log_path[PATH_MAX];
static char error_log_path[PATH_MAX];
static char sql_log_path[PATH_MAX];
static char debug_log_path[PATH_MAX];

FCGX_Stream *fcgx_in;
FCGX_Stream *fcgx_out;
FCGX_Stream *fcgx_err;
FCGX_ParamArray fcgx_envp;

FILE *access_log;
FILE *sql_log;
FILE *error_log;
FILE *debug_log;

struct user_session user_session;
struct env_vars env_vars;

const struct cfg *cfg;

/*
 * Decide how many worker processes should be created.
 *
 * If we have a specified number in the config file (NR_PROCS), use
 * that.
 *
 * Else try getting the number of available processors and fork one
 * process per processor.
 *
 * Else just create a single worker.
 */
static int get_nr_procs(void)
{
	if (cfg->nr_procs > 0)
		return cfg->nr_procs;
	else if (get_nprocs() > 0)
		return get_nprocs();

	return 1;
}

/*
 * This function will change the process name to 'title'
 *
 * This is likely to only work on Linux and basically just makes a
 * copy of the environment and clobbers the old one with the new name.
 *
 * Based on code from; nginx
 */
static void set_proc_title(const char *title)
{
	size_t size = 0;
	int i;
	char *p;
	char *argv_last;

	for (i = 0; environ[i]; i++)
		size += strlen(environ[i]) + 1;

	p = malloc(size);
	if (!p) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	argv_last = rargv[0] + strlen(rargv[0]) + 1;

	for (i = 0; rargv[i]; i++) {
		if (argv_last == rargv[i])
			argv_last = rargv[i] + strlen(rargv[i]) + 1;
	}

	for (i = 0; environ[i]; i++) {
		if (argv_last == environ[i]) {
			size = strlen(environ[i]) + 1;
			argv_last = environ[i] + size;

			snprintf(p, size, "%s", environ[i]);
			environ[i] = p;
			p += size;
		}
	}
	argv_last--;

	rargv[1] = NULL;
	p = strncpy(rargv[0], title, argv_last - rargv[0]);
}

/*
 * Signal handler for SIGUSR2, sets a flag to inform that
 * dump_sessions_state() should be run.
 */
static void sh_dump_session_state(int signo)
{
	dump_sessions = 1;
}

/*
 * Dumps session state upon receiving a SIGUSR2
 */
static void dump_session_state(void)
{
	TCTDB *tdb;
	TDBQRY *qry;
	TCLIST *res;
	int i;
	int nres;

	tdb = tctdbnew();
	tctdbopen(tdb, cfg->session_db, TDBOREADER);

	qry = tctdbqrynew(tdb);
	res = tctdbqrysearch(qry);
	nres = tclistnum(res);
	fprintf(debug_log, "Number of active sessions: %d\n", nres);
	for (i = 0; i < nres; i++) {
		int rsize;
		const char *rbuf = tclistval(res, i, &rsize);
		TCMAP *cols = tctdbget(tdb, rbuf, rsize);
		unsigned char capabilities = atoi(tcmapget2(
					cols, "capabilities"));

		tcmapiterinit(cols);

		fprintf(debug_log, "\ttenant       : %s\n", tcmapget2(cols,
					"tenant"));
		fprintf(debug_log, "\tsid          : %s\n", tcmapget2(cols,
					"sid"));
		fprintf(debug_log, "\tuid          : %s\n", tcmapget2(cols,
					"uid"));
		fprintf(debug_log, "\tcapabilities : %d\n", capabilities);
		fprintf(debug_log, "\tusername     : %s\n", tcmapget2(cols,
					"username"));
		fprintf(debug_log, "\tname         : %s\n", tcmapget2(cols,
					"name"));
		fprintf(debug_log, "\tlogin_at     : %s\n", tcmapget2(cols,
					"login_at"));
		fprintf(debug_log, "\tlast_seen    : %s\n", tcmapget2(cols,
					"last_seen"));
		fprintf(debug_log, "\torigin_ip    : %s\n", tcmapget2(cols,
					"origin_ip"));
		fprintf(debug_log, "\tclient_id    : %s\n", tcmapget2(cols,
					"client_id"));
		fprintf(debug_log, "\tsession_id   : %s\n", tcmapget2(cols,
					"session_id"));
		fprintf(debug_log, "\tcsrf_token   : %s\n", tcmapget2(cols,
					"csrf_token"));
		fprintf(debug_log, "\trestrict_ip  : %s\n\n",
				tcmapget2(cols, "restrict_ip")[0] == '1' ?
				"true" : "false");
		tcmapdel(cols);
	}
	tclistdel(res);
	tctdbqrydel(qry);

	tctdbclose(tdb);
	tctdbdel(tdb);

	fflush(debug_log);

	dump_sessions = 0;
}

/*
 * Signal handler to handle child process terminations.
 */
static void reaper(int signo)
{
	int status;

	/*
	 * Make sure we catch multiple children terminating at the same
	 * time as we will only get one SIGCHLD while in this handler.
	 */
	while (waitpid(-1, &status, WNOHANG) > 0) {
		/*
		 * If a process dies, create a new one.
		 *
		 * However, don't create new processes if we get a
		 * SIGTERM or SIGKILL signal as that will stop the
		 * thing from being shutdown.
		 */
		if (WIFSIGNALED(status) &&
		    (WTERMSIG(status) != SIGTERM &&
		     WTERMSIG(status) != SIGKILL))
			create_nr_new_server++;
	}
}

/*
 * Upon receiving the TERM signal, terminate all children and exit.
 */
static void terminate(int signo)
{
	kill(0, SIGTERM);
	_exit(EXIT_SUCCESS);
}

/*
 * Signal handler for SIGRTMIN, sets a flag to inform that
 * various house keeping tasks should be run.
 */
static void sh_house_keeping(int sig, siginfo_t *si, void *uc)
{
	housekeeping = 1;
}

/*
 * Clear out old sessions that haven't been accessed (last_seen) since
 * SESSION_EXPIRY ago.
 */
static void clear_old_sessions(void)
{
	TCTDB *tdb;
	TDBQRY *qry;
	TCLIST *res;
	int i;
	int nres;
	int rsize;
	char expiry[21];
	const char *rbuf;

	d_fprintf(debug_log, "Clearing old sessions\n");

	snprintf(expiry, sizeof(expiry), "%ld", time(NULL) - SESSION_EXPIRY);

	tdb = tctdbnew();
	tctdbopen(tdb, cfg->session_db, TDBOWRITER);

	qry = tctdbqrynew(tdb);
	tctdbqryaddcond(qry, "last_seen", TDBQCNUMLT, expiry);
	res = tctdbqrysearch(qry);
	nres = tclistnum(res);
	if (nres < 1)
		goto out;

	for (i = 0; i < nres; i++) {
		rbuf = tclistval(res, 0, &rsize);
		tctdbout(tdb, rbuf, strlen(rbuf));
	}

out:
	tclistdel(res);
	tctdbqrydel(qry);
	tctdbclose(tdb);
	tctdbdel(tdb);
}

static void check_dns_domain_expiry(void)
{
	unsigned long i;
	unsigned long nr_rows;
	time_t tnow = time(NULL);
	MYSQL *mc;
	MYSQL_RES *res;

	d_fprintf(debug_log, "Looking for expired DNS domains\n");

	mc = db_conn(cfg->db_host, cfg->db_name, false);
	/*
	 * Get a list of DNS domains that are due to expire within 30 days.
	 *
	 * We need to cast the expires calculation to a signed value to cater
	 * for -ve results when the current time is beyond the expiry date.
	 */
	res = sql_query(mc, "SELECT passwd.name, passwd.username AS email, "
			"pdns.domains.name AS domain, pdns.domains.type, "
			"domain_id, added, expires, notified FROM domains "
			"INNER JOIN pdns.domains ON "
			"(domain_id = pdns.domains.id) INNER JOIN passwd ON "
			"(passwd.uid = domains.uid) WHERE expired = 0 AND "
			"CAST(expires - %ld AS SIGNED) <= 86400 * 30", tnow);

	nr_rows = mysql_num_rows(res);
	for (i = 0; i < nr_rows; i++) {
		time_t tadded;
		time_t texpires;
		time_t tdiff;
		int notified;
		int domain_id;
		GHashTable *db_row = NULL;

		db_row = get_dbrow(res);
		domain_id = atoi(get_var(db_row, "domain_id"));
		notified = atoi(get_var(db_row, "notified"));
		tadded = atol(get_var(db_row, "added"));
		texpires = atol(get_var(db_row, "expires"));
		tdiff = texpires - tadded;

		if (tnow >= texpires) {
			/* Domain has expired */
			MYSQL *sconn;
			const char *r_sql = "UPDATE pdns.records SET name = "
				"CONCAT(\"!!\", name) WHERE domain_id = %d";

			sql_query(mc, "UPDATE domains SET expired = 1 WHERE "
					"domain_id = %d", domain_id);
			sql_query(mc, r_sql, domain_id);

			sconn = db_conn(cfg->db_shost, "pdns", true);
			sql_query(sconn, r_sql, domain_id);
			if (strcmp(get_var(db_row, "type"), "SLAVE") == 0) {
				const char *s_sql = "UPDATE pdns.domains SET "
					"master = CONCAT(\"!!\", master) WHERE "
					"id = %d";

				sql_query(mc, s_sql, domain_id);
				sql_query(sconn, s_sql, domain_id);
			}
			mysql_close(sconn);

			send_expired_mail(get_var(db_row, "name"),
					get_var(db_row, "email"),
					get_var(db_row, "domain"),
					"DNS", texpires);
		} else if (!notified && tdiff <= 86400 * 30) {
			if (texpires - tnow <= 86400 * 14) {
				send_expiry_mail(get_var(db_row, "name"),
						get_var(db_row, "email"),
						get_var(db_row, "domain"),
						"DNS", texpires);
				sql_query(mc, "UPDATE domains SET notified "
						"= 1 WHERE domain_id = %d",
						domain_id);
			}
		} else if (!notified && texpires - tnow <= 86400 * 30) {
				send_expiry_mail(get_var(db_row, "name"),
						get_var(db_row, "email"),
						get_var(db_row, "domain"),
						"DNS", texpires);
				sql_query(mc, "UPDATE domains SET notified "
						"= 1 WHERE domain_id = %d",
						domain_id);
		}
		free_vars(db_row);
	}

	mysql_free_result(res);
	mysql_close(mc);
}

static void check_mail_domain_expiry(void)
{
	unsigned long i;
	unsigned long nr_rows;
	time_t tnow = time(NULL);
	MYSQL *mc;
	MYSQL_RES *res;

	d_fprintf(debug_log, "Looking for expired Mail domains\n");

	mc = db_conn(cfg->db_host, cfg->db_name, false);
	/*
	 * Get a list of Mail domains that are due to expire within 30 days.
	 *
	 * We need to cast the expires calculation to a signed value to cater
	 * for -ve results when the current time is beyond the expiry date.
	 */
	res = sql_query(mc, "SELECT passwd.name, passwd.username AS email, "
			"domain, domain_id, type, added, expires, notified "
			"FROM mail_domains INNER JOIN passwd ON "
			"(passwd.uid = mail_domains.uid) WHERE expired = 0 "
			"AND CAST(expires - %ld AS SIGNED) <= 86400 * 30",
			tnow);

	nr_rows = mysql_num_rows(res);
	for (i = 0; i < nr_rows; i++) {
		time_t tadded;
		time_t texpires;
		time_t tdiff;
		int notified;
		int domain_id;
		const char *m_type;
		GHashTable *db_row = NULL;

		db_row = get_dbrow(res);
		domain_id = atoi(get_var(db_row, "domain_id"));
		m_type = get_var(db_row, "type");
		notified = atoi(get_var(db_row, "notified"));
		tadded = atol(get_var(db_row, "added"));
		texpires = atol(get_var(db_row, "expires"));
		tdiff = texpires - tadded;

		if (tnow >= texpires) {
			/* Domain has expired */
			MYSQL *sconn;

			sql_query(mc, "UPDATE mail_domains SET expired = 1 "
					"WHERE domain_id = %d", domain_id);

			sconn = db_conn(cfg->db_shost, "postfix", true);
			if (strcmp(m_type, "MX") == 0) {
				sql_query(sconn, "UPDATE "
						"postfix.relay_domains SET "
						"enabled = 0 WHERE domain_id "
						"= %d", domain_id);
			} else {
				const char *f_sql = "UPDATE "
					"postfix.local_domains SET enabled = 0 "
					"WHERE domain_id = %d";

				sql_query(mc, f_sql, domain_id);
				sql_query(sconn, f_sql, domain_id);
			}
			mysql_close(sconn);

			send_expired_mail(get_var(db_row, "name"),
					get_var(db_row, "email"),
					get_var(db_row, "domain"),
					"Mail", texpires);
		} else if (!notified && tdiff <= 86400 * 30) {
			if (texpires - tnow <= 86400 * 14) {
				send_expiry_mail(get_var(db_row, "name"),
						get_var(db_row, "email"),
						get_var(db_row, "domain"),
						"Mail", texpires);
				sql_query(mc, "UPDATE mail_domains SET "
						"notified = 1 WHERE domain_id "
						"= %d", domain_id);
			}
		} else if (!notified && texpires - tnow <= 86400 * 30) {
				send_expiry_mail(get_var(db_row, "name"),
						get_var(db_row, "email"),
						get_var(db_row, "domain"),
						"Mail", texpires);
				sql_query(mc, "UPDATE mail_domains SET "
						"notified = 1 WHERE domain_id "
						"= %d", domain_id);
		}
		free_vars(db_row);
	}

	mysql_free_result(res);
	mysql_close(mc);
}

static void clear_pending_activations(void)
{
	MYSQL *mc;

	mc = db_conn(cfg->db_host, cfg->db_name, false);
	sql_query(mc, "DELETE FROM pending_activations WHERE %ld > expires",
		  time(NULL));
	mysql_close(mc);
}

static void clear_pending_ipacl_deact(void)
{
	MYSQL *mc;

	mc = db_conn(cfg->db_host, cfg->db_name, false);
	sql_query(mc, "DELETE FROM pending_ipacl_deact WHERE %ld > expires",
		  time(NULL));
	mysql_close(mc);
}

static void house_keeping(void)
{
	time_t tnow = time(NULL);
	struct tm *tm = gmtime(&tnow);

	if (tm->tm_hour == 0) {
		check_dns_domain_expiry();
		check_mail_domain_expiry();
	}

	clear_pending_activations();
	clear_pending_ipacl_deact();
	clear_old_sessions();

	housekeeping = 0;
}

/*
 * Sets up a timer to clear old sessions. Fires every SESSION_CHECK seconds.
 */
static void init_house_keeping_timer(void)
{
	timer_t timerid;
	struct sigevent sev;
	struct itimerspec its;
	struct sigaction action;

	sigemptyset(&action.sa_mask);
	action.sa_flags = SA_RESTART;
	action.sa_sigaction = sh_house_keeping;
	sigaction(SIGRTMIN, &action, NULL);

	sev.sigev_notify = SIGEV_SIGNAL;
	sev.sigev_signo = SIGRTMIN;
	sev.sigev_value.sival_ptr = &timerid;
	timer_create(CLOCK_MONOTONIC, &sev, &timerid);

	its.it_value.tv_sec = H_K_INT;
	its.it_value.tv_nsec = 0;
	its.it_interval.tv_sec = its.it_value.tv_sec;
	its.it_interval.tv_nsec = its.it_value.tv_nsec;

	timer_settime(timerid, 0, &its, NULL);
}

/*
 * Signal handler for SIGHUP, sets a flag to inform that
 * the log files should be closed and reopened for log file
 * rotation.
 */
static void sh_rotate_log_files(int signo)
{
	rotate_log_files = 1;
}

static void init_logs(void)
{
	mode_t smask;

	if (rotate_log_files) {
		d_fprintf(debug_log,
			  "logrotation: closing and re-opening log files\n");

		fclose(access_log);
		fclose(error_log);
		fclose(sql_log);
		fclose(debug_log);

		rotate_log_files = 0;
	} else {
		int err;

		err = access(cfg->log_dir, R_OK | W_OK | X_OK);
		if (err == -1)
			exit(EXIT_FAILURE);
		snprintf(access_log_path, PATH_MAX, "%s/access.log",
			 cfg->log_dir);
		snprintf(error_log_path, PATH_MAX, "%s/error.log",
			 cfg->log_dir);
		snprintf(sql_log_path, PATH_MAX, "%s/sql.log", cfg->log_dir);
		snprintf(debug_log_path, PATH_MAX, "%s/debug.log",
			 cfg->log_dir);
	}

	/* Create the log files as -rw-r----- */
	smask = umask(0027);
	access_log = fopen(access_log_path, "a");
	error_log = fopen(error_log_path, "a");
	sql_log = fopen(sql_log_path, "a");
	debug_log = fopen(debug_log_path, "a");
	umask(smask);

	/* Make stderr point to the error_log */
	dup2(fileno(error_log), STDERR_FILENO);
}

/*
 * Send a SIGHUP signal to the worker processes to notify them
 * about log file rotation.
 *
 * Close and re-open the log files.
 *
 * This function should _only_ be called from the master process.
 * The worker processes should just call init_logs() directly.
 */
static void logfile_rotation(void)
{
	sigset_t hup;

	/*
	 * We don't want the master process receiving the
	 * HUP signal itself.
	 */
	sigemptyset(&hup);
	sigaddset(&hup, SIGHUP);
	sigprocmask(SIG_BLOCK, &hup, NULL);
	kill(0, SIGHUP);
	sigprocmask(SIG_UNBLOCK, &hup, NULL);

	init_logs();
}

/*
 * Main program loop. This sits in accept() waiting for connections.
 */
static void accept_request(void)
{
	/*
	 * We use SIGUSR2 to dump the session state which we only want
	 * handled by the parent process. Ignore it in the children.
	 */
	signal(SIGUSR2, SIG_IGN);
	/*
	 * We use SIGRTMIN to clear out old sessions. This signal is
	 * produced by a timer. We only want this signal handled in the
	 * parent so ignore it in the children.
	 */
	signal(SIGRTMIN, SIG_IGN);

	while (FCGX_Accept(&fcgx_in, &fcgx_out, &fcgx_err, &fcgx_envp) >= 0) {
		if (rotate_log_files)
			init_logs();
		handle_request();
		FCGX_Finish();
	}

	/* If we get here, something went wrong */
	_exit(EXIT_FAILURE);
}

/*
 * Create nr server processes.
 */
static void create_server(int nr)
{
	int i;

	for (i = 0; i < nr; i++) {
		pid_t pid;

		pid = fork();
		if (pid == 0) {  /* child */
			set_proc_title("dax: worker");
			accept_request();
		}
	}

	create_nr_new_server = 0;
}

int main(int argc, char **argv)
{
	struct sigaction action;
	int ret;

	/* Used by set_proc_title() */
	rargv = argv;

	cfg = get_config(argv[1]);
	if (!cfg)
		exit(EXIT_FAILURE);

	/* Set the log paths and open them */
	init_logs();

	ret = mysql_library_init(0, NULL, NULL);
	if (ret) {
		d_fprintf(error_log, "mysql: could not initialise library.\n");
		goto close_logs;
	}

	/* Ignore SIGPIPE as per the fastcgi faq */
	signal(SIGPIPE, SIG_IGN);

	/* Setup signal handler for SIGHUP for logfile rotation */
	sigemptyset(&action.sa_mask);
	action.sa_handler = sh_rotate_log_files;
	action.sa_flags = SA_RESTART;
	sigaction(SIGHUP, &action, NULL);

	/* Setup signal handler for SIGUSR2 to dump session state */
	sigemptyset(&action.sa_mask);
	action.sa_handler = sh_dump_session_state;
	action.sa_flags = SA_RESTART;
	sigaction(SIGUSR2, &action, NULL);

	/*
	 * Setup a signal handler for SIGTERM to terminate all the
	 * child processes.
	 */
	sigemptyset(&action.sa_mask);
	action.sa_handler = terminate;
	action.sa_flags = 0;
	sigaction(SIGTERM, &action, NULL);

	/*
	 * Setup a signal handler for SIGCHLD to handle child
	 * process terminations.
	 */
	sigemptyset(&action.sa_mask);
	action.sa_handler = reaper;
	action.sa_flags = 0;
	sigaction(SIGCHLD, &action, NULL);

	init_house_keeping_timer();

	/* Pre-fork worker processes */
	create_server(get_nr_procs());

	/* Set the process name for the master process */
	set_proc_title("dax: master");

	/*
	 * To make the signal handlers as simple as possible and
	 * reentrant safe, they just set flags to say what should
	 * be done.
	 *
	 * The simplest way to check these is to wake up periodically, which
	 * is what we currently do. The more complex way is the self-pipe
	 * trick. p. 1370, The Linux Programming Interface - M. Kerrisk
	 *
	 * Changed from sleep() to pause() which matches more what we want.
	 */
	for (;;) {
		pause();
		if (create_nr_new_server)
			create_server(create_nr_new_server);
		if (dump_sessions)
			dump_session_state();
		if (housekeeping)
			house_keeping();
		if (rotate_log_files)
			logfile_rotation();
	}

	mysql_library_end();

close_logs:
	fclose(access_log);
	fclose(error_log);
	fclose(sql_log);
	fclose(debug_log);

	/* We shouldn't run through to here */
	exit(EXIT_FAILURE);
}
