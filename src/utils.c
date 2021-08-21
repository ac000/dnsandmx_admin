/*
 * utils.c
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
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netdb.h>

#include <glib.h>

#include <gmime/gmime.h>

#include <mhash.h>

#include <fcgiapp.h>

/* HTML template library */
#include <ctemplate.h>

#include "common.h"
#include "audit.h"
#include "utils.h"

struct quark {
	GHashTable *q;
	int last;
};
static struct quark quarks;

/* Linked list to store file_info structures. */
GList *u_files;
/*
 * Linked list to hold hash tables of name=value pairs of POST array
 * variables.
 */
GList *avars;
/* Hash table to hold name=value pairs of POST/GET variables. */
GHashTable *qvars;

/*
 * A simplified version of GLibs GQuark.
 *
 * Maps strings to integers starting at 0. The same string will map to the
 * same integer.
 */
static int quark_from_string(const char *str)
{
	gpointer q;

	if (!quarks.q) {
		quarks.q = g_hash_table_new_full(g_str_hash, g_str_equal,
						 g_free, NULL);
		quarks.last = 0;
	}

	q = g_hash_table_lookup(quarks.q, str);
	if (!q) {
		quarks.last += 1;
		g_hash_table_insert(quarks.q, g_strdup(str),
				    GINT_TO_POINTER(quarks.last));

		return quarks.last - 1;
	} else {
		return GPOINTER_TO_INT(q) - 1;
	}
}

/*
 * Given a host and domain name, return the combined Fully Qualified
 * Domain Name in buf
 */
void make_fqdn(const char *host, const char *domain, char *buf, size_t sz)
{
	int len = 0;

	if (IS_SET(host))
		len = snprintf(buf, sz, "%s.", host);
	snprintf(buf + len, sz - len, "%s", domain);
}

/*
 * Given a hostmaster address, convert this back into an email address
 * e.g
 *
 * andrew\.clayton.digital-domain.net -> andrew.clayton@digital-domain.net
 */
char *hostmaster_to_email(const char *hostmaster, char *email)
{
	int i = 0;
	bool escaped;
	bool domain = false;

	while (*hostmaster) {
		if (*hostmaster == '\\') {
			hostmaster++;
			escaped = true;
		} else {
			escaped = false;
		}

		if (*hostmaster == '.' && (escaped || domain)) {
			email[i] = '.';
		} else if (*hostmaster == '.') {
			email[i] = '@';
			domain = true;
		} else {
			email[i] = *hostmaster;
		}
		hostmaster++;
		i++;
	}
	email[i] = '\0';

	return email;
}

/*
 * Given an email address convert into a format suitable for use in a SOA
 * record. i.e convert the the @ to a '.' and escape any .'s in the name
 * part e.g
 *
 * andrew.clayton@digital-domain.net -> andrew\.clayton.digital-domain.net
 */
char *email_to_hostmaster(const char *email, char *hostmaster)
{
	int i = 0;

	if (!strstr(email, "@")) {
		strcpy(hostmaster, email);
		return hostmaster;
	}

	while (*email != '@') {
		if (*email == '.') {
			hostmaster[i] = '\\';
			hostmaster[++i] = *email;
		} else {
			hostmaster[i] = *email;
		}
		email++;
		i++;
	}
	hostmaster[i++] = '.';
	strcpy(hostmaster + i, email + 1);

	return hostmaster;
}

/*
 * Strips trailing '.'s from a string
 */
char *dotchomp(char *string)
{
	size_t len = strlen(string);

	if (string[len - 1] == '.')
		string[len - 1] = '\0';

	return string;
}

/*
 * Given a domain name, try to work out if it is a forward ro reverse zone.
 * Reverse zones, would be like;
 *
 * 	in-addr.arpa
 * 	in6.arpa
 * 	e164.arpa
 */
bool is_reverse_zone(const char *domain)
{
	if (strcasestr(domain, "e164.arpa"))
		return true;
	else if (strcasestr(domain, "in-addr.arpa"))
		return true;
	else if (strcasestr(domain, "in6.arpa"))
		return true;

	return false;
}

/*
 * A simple check to see if a given IPv6 address is valid.
 */
bool is_valid_ipv6_addr(const char *addr)
{
	if (!strchr(addr, ':'))
		return false;

	while (*addr) {
		if (!isxdigit(*addr) && *addr != ':')
			return false;
		addr++;
	}

	return true;
}

/*
 * A simple check to see if a given IPv4 address is valid.
 */
bool is_valid_ipv4_addr(const char *addr)
{
	char *token;
	char *string;
	size_t len = strlen(addr);
	int bits = 0;

	while (*addr) {
		if (!isdigit(*addr) && *addr != '.')
			return false;
		addr++;
	}
	addr -= len;

	string = strdup(addr);
	token = strtok(string, ".");
	while (token != NULL) {
		int quad;

		quad = atoi(token);
		bits++;
		if (quad < 0 || quad > 255 || bits > 4)
			break;
		token = strtok(NULL, ".");
	}
	free(string);

	if (bits == 4)
		return true;
	else
		return false;
}

/*
 * Given a hostname, check that it is valid according to
 * RFC's 952 and 1123.
 *
 * Essentially it comes down to: [a-z0-9](*[a-z0-9-])[a-z0-9]
 * and must be no more than 63 characters long.
 */
bool is_valid_hostname(const char *hostname)
{
	/* Allow wildcards */
	if (strcmp(hostname, "*") == 0)
		return true;

	if (strstr(hostname, ".."))
		return false;

	/* Length check */
	if (strlen(hostname) < 1 || strlen(hostname) >= NI_MAXHOST)
		return false;

	/* First character check */
	if (!isdigit(*hostname) && !isalpha(*hostname))
		return false;

	/* Main check */
	hostname++;
	while (*hostname) {
		if (!isdigit(*hostname) &&
		    !isalpha(*hostname) &&
		    *hostname != '-' &&
		    *hostname != '.')
			return false;
		hostname++;
	}
	/* Last character check */
	hostname--;
	if (*hostname == '-')
		return false;

	return true;
}

/*
 * A basic check for something that looks like a valid email address.
 */
bool is_valid_email_address(const char *email_addr)
{
	bool ret = false;
	char *p;

	if (strlen(email_addr) < 3)
		goto out;

	if (email_addr[strlen(email_addr) - 1] == '.')
		goto out;

	p = strstr(email_addr, "@");
	if (!p) {
		goto out;
	} else {
		if (*(++p) == '.')
			goto out;
		else
			ret = true;
	}

out:
	return ret;
}

/*
 * Checks if a given domain belongs to the user in question.
 */
bool is_users_domain(int domain_id, const char *table)
{
	MYSQL_RES *res;
	bool ret = false;

	res = sql_query(conn, "SELECT domain_id FROM %s WHERE uid = %u AND "
			"domain_id = %d", table, user_session.uid, domain_id);

	if (mysql_num_rows(res) == 1)
		ret = true;
	mysql_free_result(res);

	return ret;
}

/*
 * Checks if a domain is editable. A domain is editable if it is the
 * users domain and is is NOT expired.
 */
bool is_domain_editable(int domain_id, const char *table)
{
	MYSQL_RES *res;
	bool ret = false;

	res = sql_query(conn, "SELECT domain_id FROM %s WHERE uid = %u AND "
			"domain_id = %d AND expired = 0", table,
			user_session.uid, domain_id);

	if (mysql_num_rows(res) == 1)
		ret = true;
	mysql_free_result(res);

	return ret;
}

/*
 * Function comes from: http://www.geekhideout.com/urlcode.shtml
 * Will replace with g_uri_unescape_string() from glib when we have
 * glib 2.16
 *
 * Converts a hex character to its integer value
 */
static char from_hex(char ch)
{
	return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
}

/*
 * Function comes from: http://www.geekhideout.com/urlcode.shtml
 * Will replace with g_uri_unescape_string() from glib when we have
 * glib 2.16
 *
 * Returns a url-decoded version of str
 *
 * IMPORTANT: be sure to free() the returned string after use
 */
static char *url_decode(const char *str)
{
	char *buf;
	char *pbuf;

	buf = malloc(strlen(str) + 1);
	if (!buf) {
		perror("malloc");
		_exit(EXIT_FAILURE);
	}
	pbuf = buf;

	while (*str) {
		if (*str == '%') {
			if (str[1] && str[2]) {
				*pbuf++ = from_hex(str[1]) << 4 |
					from_hex(str[2]);
				str += 2;
			}
		} else if (*str == '+') {
			*pbuf++ = ' ';
		} else {
			*pbuf++ = *str;
		}
		str++;
	}
	*pbuf = '\0';

	return buf;
}

/*
 * Given a hostname like host.example.com it returns just 'host'
 */
char *get_tenant(const char *host, char *tenant)
{
	char *str;

	if (!MULTI_TENANT || !host) {
		/*
		 * We are either not in multi-tenancy mode and/or being run
		 * due to a signal handler.
		 */
		strcpy(tenant, "");
		goto out;
	}

	str = strdupa(host);
	snprintf(tenant, TENANT_MAX + 1, "%s", strsep(&str, "."));

out:
	return tenant;
}

/*
 * Given a username return the real name, which should be free'd.
 */
char *username_to_name(const char *username)
{
	char *who;
	char *name;
	MYSQL_RES *res;
	MYSQL_ROW row;

	who = make_mysql_safe_string(username);
	res = sql_query(conn, "SELECT name FROM passwd WHERE username = '%s'",
			who);
	row = mysql_fetch_row(res);

	name = strdup(row[0]);

	mysql_free_result(res);
	free(who);

	return name;
}

/*
 * Generates a hash of the specified type, using /dev/urandom as a
 * source of entropy.
 *
 * It plaves the resultant hash in hash and also returns a pointer
 * to it.
 */
char *generate_hash(char *hash, int type)
{
	int fd;
	int i;
	int hbs;
	int len = 0;
	int hash_len;
	ssize_t bytes_read;
	char buf[ENTROPY_SIZE];
	unsigned char *xhash;
	MHASH td;

	fd = open("/dev/urandom", O_RDONLY);
	bytes_read = read(fd, &buf, sizeof(buf));
	close(fd);

	if (bytes_read < sizeof(buf)) {
		/*
		 * If we couldn't read the required amount, something is
		 * seriously wrong. Log it and exit.
		 */
		d_fprintf(error_log, "Couldn't read sufficient data from "
				"/dev/urandom\n");
		_exit(EXIT_FAILURE);
	}

	switch (type) {
	case SHA1:
		td = mhash_init(MHASH_SHA1);
		hbs = mhash_get_block_size(MHASH_SHA1);
		hash_len = SHA1_LEN;
		break;
	case SHA256:
		td = mhash_init(MHASH_SHA256);
		hbs = mhash_get_block_size(MHASH_SHA256);
		hash_len = SHA256_LEN;
		break;
	default:
		td = mhash_init(MHASH_SHA1);
		hbs = mhash_get_block_size(MHASH_SHA1);
		hash_len = SHA1_LEN;
	}
	mhash(td, &buf, sizeof(buf));
	xhash = mhash_end(td);

	memset(hash, 0, hash_len + 1);
	for (i = 0; i < hbs; i++)
		len += snprintf(hash + len, 3, "%.2x", xhash[i]);
	free(xhash);

	return hash;
}

/*
 * Free's the avars GList
 */
void free_avars(void)
{
	unsigned int i;
	unsigned int size;

	if (quarks.q) {
		g_hash_table_destroy(quarks.q);
		quarks.q = NULL;
	}

	if (!avars)
		return;

	size = g_list_length(avars);
	for (i = 0; i < size; i++) {
		GHashTable *query_vars = g_list_nth_data(avars, i);
		g_hash_table_destroy(query_vars);
	}
	g_list_free(avars);
}

/*
 * Free's the given GHashTable
 */
void free_vars(GHashTable *vars)
{
	if (vars != NULL)
		g_hash_table_destroy(vars);
}

/*
 * Free's the u_files GList
 */
void free_u_files(void)
{
	unsigned int i;
	unsigned int size;

	if (!u_files)
		return;

	size = g_list_length(u_files);
	for (i = 0; i < size; i++) {
		struct file_info *file_info = g_list_nth_data(u_files, i);
		unlink(file_info->temp_file_name);
		free(file_info->name);
		free(file_info->mime_type);
		free(file_info);
	}
	g_list_free(u_files);
}

/*
 * Add's a name=value pair to the GList (avars) of array POST
 * variables.
 *
 * These ones come from data POST'd as multipart/form-data
 *
 * This data is _not_ % encoded and does not require to be run
 * through url_decode. It also means we need to split on [ and
 * not its %value.
 */
static void add_multipart_avar(const char *name, const char *value)
{
	char *token;
	char *string;
	GHashTable *ht;
	bool new = false;
	int qidx;

	string = strdupa(name);

	token = strtok(string, "[");
	qidx = quark_from_string(token);
	/*
	 * Look for an existing hash table for this variable index. We
	 * use qidx - 1 for the array position as GQuark's start at 1
	 */
	ht = g_list_nth_data(avars, qidx);
	if (!ht) {
		/* New array index, new hash table */
		ht = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
					   g_free);
		new = true;
	}

	token = NULL;
	token = strtok(token, "=");

	d_fprintf(debug_log, "Adding key: %s with value: %s\n", token, value);
	g_hash_table_replace(ht, g_strdup(token), g_strdup(value));
	if (new)
		avars = g_list_append(avars, ht);
}

/*
 * Add's a name=value pair to the GHashTable (qvars) of name=value
 * pairs of data POST'd with multipart/form-data.
 *
 * This data is _not_ % encoded and does not require to be run
 * through url_decode.
 */
static void add_multipart_var(const char *name, const char *value)
{
	d_fprintf(debug_log, "Adding key: %s with value: %s\n", name, value);
	if (!qvars)
		qvars = g_hash_table_new_full(g_str_hash, g_str_equal,
							g_free, g_free);
	g_hash_table_replace(qvars, g_strdup(name), g_strdup(value));
}

/*
 * Add's a name=value pair to the GList (avars) of POST array variables.
 *
 * This is data that has been POST'd as x-www-form-urlencoded
 */
static void add_avar(const char *qvar)
{
	char *token;
	char *string;
	char *key;
	char *value;
	GHashTable *ht;
	bool new = false;
	int qidx;

	string = strdupa(qvar);

	token = strtok(string, "%");
	qidx = quark_from_string(token);
	/*
	 * Look for an existing hash table for this variable index. We
	 * use qidx - 1 for the array position as GQuark's start at 1
	 */
	ht = g_list_nth_data(avars, qidx);
	if (!ht) {
		/* New array index, new hash table */
		ht = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
					   g_free);
		new = true;
	}

	token = NULL;
	token = strtok(token, "=");
	key = malloc(strlen(token));
	memset(key, 0, strlen(token));
	snprintf(key, strlen(token + 2) - 2, "%s", token + 2);
	token = NULL;

	token = strtok(token, "=");
	if (token)
		value = url_decode(token);
	else
		value = url_decode("");

	d_fprintf(debug_log, "Adding key: %s with value: %s\n", key, value);
	g_hash_table_replace(ht, key, value);
	if (new)
		avars = g_list_append(avars, ht);
}

/*
 * Add's a name=value pair to the GHashTable (qvars) of name=value
 * pairs of data from GET or POST (x-www-form-urlencoded)
 */
static void add_var(const char *qvar)
{
	char *string;
	char *token;
	char *key;
	char *value;

	if (!qvars)
		qvars = g_hash_table_new_full(g_str_hash, g_str_equal,
				g_free, g_free);

	string = strdupa(qvar);

	token = strtok(string, "=");
	key = token;
	token = NULL;

	token = strtok(token, "=");
	if (token)
		value = url_decode(token);
	else
		value = url_decode("");

	d_fprintf(debug_log, "Adding key: %s with value: %s\n", key, value);
	g_hash_table_replace(qvars, g_strdup(key), value);
}

/*
 * Determine whether a POST/GET variable is an array variable or not
 * and call the appropriate function to add it to the right data
 * structure.
 *
 * Array variables go to avars.
 * Non array variables go to qvars.
 */
static void process_vars(const char *query)
{
	char *token;
	char *saveptr1 = NULL;
	char *string;

	string = strdupa(query);
	token = strtok_r(string, "&", &saveptr1);
	while (token != NULL) {
		if (strstr(token, "%5D="))
			add_avar(token);
		else
			add_var(token);
		token = strtok_r(NULL, "&", &saveptr1);
	}
}

/*
 * Extract data from POST multipart/form-data
 *
 * This will extract files and variable name/data pairs.
 */
static void process_mime_part(GMimeObject *parent, GMimeObject *part,
			      gpointer user_data)
{
	GMimeContentType *content_type;
	GMimeStream *stream;
	GMimeDataWrapper *content;
	GMimeContentDisposition *disposition;
	const char *dfname;
	const char *dname;

	content_type = g_mime_object_get_content_type(part);
	disposition = g_mime_content_disposition_new_from_string(
			g_mime_object_get_header(part, "Content-Disposition"));

	dname = g_mime_content_disposition_get_parameter(disposition, "name");
	dfname = g_mime_content_disposition_get_parameter(disposition,
			"filename");
	if (dfname) {
		char temp_name[] = "/tmp/u_files/pgv-XXXXXX";
		struct file_info *file_info;
		int fd;
		mode_t smask;

		/* Ensure we create the file restrictively */
		smask = umask(0077);
		fd = mkstemp(temp_name);
		umask(smask);

		file_info = malloc(sizeof(struct file_info));
		memset(file_info, 0, sizeof(struct file_info));
		snprintf(file_info->orig_file_name,
			 sizeof(file_info->orig_file_name), "%s", dname);
		strcpy(file_info->temp_file_name, temp_name);
		file_info->name = strdup(dname);
		file_info->mime_type = strdup(g_mime_content_type_to_string(
					content_type));

		stream = g_mime_stream_fs_new(fd);
		content = g_mime_part_get_content_object((GMimePart *)part);
		g_mime_data_wrapper_write_to_stream(content, stream);
		g_mime_stream_flush(stream);
		close(fd);

		u_files = g_list_append(u_files, file_info);
	} else {
		char *buf;
		ssize_t bytes;

		stream = g_mime_stream_mem_new();
		content = g_mime_part_get_content_object((GMimePart *)part);
		bytes = g_mime_data_wrapper_write_to_stream(content, stream);

		buf = malloc(bytes + 1);
		g_mime_stream_seek(stream, 0, GMIME_STREAM_SEEK_SET);
		g_mime_stream_read(stream, buf, bytes);
		buf[bytes] = '\0';

		if (strstr(dname, "["))
			add_multipart_avar(dname, buf);
		else
			add_multipart_var(dname, buf);
		free(buf);
	}

	g_object_unref(content);
	g_object_unref(stream);
	g_object_unref(disposition);
}

/*
 * Handle POST multipart/form-data
 *
 * process_mime_part() is called for each part of the data.
 */
static void process_mime(void)
{
	char *data;
	off_t size = 0;
	off_t content_length = env_vars.content_length;
	int bytes_read;
	GMimeStream *stream;
	GMimeParser *parser;
	GMimeObject *parts;

	if (!content_length)
		return;

	data = calloc(content_length, 1);
	do {
		bytes_read = fcgx_gs(data + size, BUF_SIZE);
		size += bytes_read;
	} while (bytes_read > 0);

	g_mime_init(0);
	stream = g_mime_stream_mem_new();
	/* We need to add the Content-Type header, for gmime */
	g_mime_stream_printf(stream, "Content-Type: %s\r\n",
			env_vars.content_type);
	g_mime_stream_write(stream, data, size);
	free(data);
	g_mime_stream_seek(stream, 0, GMIME_STREAM_SEEK_SET);

	parser = g_mime_parser_new_with_stream(stream);
	parts = g_mime_parser_construct_part(parser);
	g_mime_multipart_foreach((GMimeMultipart *)parts,
				 (GMimeObjectForeachFunc)process_mime_part,
				 NULL);

	g_object_unref(stream);
	g_object_unref(parser);
	g_mime_shutdown();
}

/*
 * Determine what type of data we got sent and build the POST/GET
 * variable data structures. avars, qvars & u_files
 *
 * We currently handle three types of data
 *
 * GET
 * POST x-www-form-urlencoded
 * POST multipart/form-data
 */
void set_vars(const char *pbuf)
{
	char buf[BUF_SIZE];

	memset(buf, 0, sizeof(buf));

	if (IS_SET(env_vars.query_string)) {
		snprintf(buf, BUF_SIZE, "%s", env_vars.query_string);
		process_vars(buf);
	}

	if (strstr(env_vars.content_type, "x-www-form-urlencoded"))
		process_vars(pbuf);
	else if (strstr(env_vars.content_type, "multipart/form-data"))
		process_mime();
}

/*
 * Create a hash table of field name=value pairs for a mysql row result set.
 */
GHashTable *get_dbrow(MYSQL_RES *res)
{
	unsigned int num_fields;
	unsigned int i;
	MYSQL_ROW row;
	MYSQL_FIELD *fields;
	GHashTable *db_row;

	db_row = g_hash_table_new_full(g_str_hash, g_str_equal,
			g_free, g_free);

	num_fields = mysql_num_fields(res);
	fields = mysql_fetch_fields(res);
	row = mysql_fetch_row(res);
	for (i = 0; i < num_fields; i++) {
		d_fprintf(debug_log, "Adding key: %s with value: %s to "
				"hash table\n", fields[i].name, row[i]);
		g_hash_table_insert(db_row, g_strdup(fields[i].name),
				g_strdup(row[i]));
	}

	return db_row;
}

/*
 * Given an index and a key, return the coresponding value from
 * the hash table contained within the avars GList.
 */
const char *get_avar(int index, const char *key)
{
	char *val;
	GHashTable *vars;

	vars = g_list_nth_data(avars, index);
	val = g_hash_table_lookup(vars, key);

	return val;
}

/*
 * Given a key name, return its value from the given hash table.
 */
const char *get_var(GHashTable *vars, const char *key)
{
	char *val;

	if (!vars)
		goto out_err;

	val = g_hash_table_lookup(vars, key);
	if (!val)
		goto out_err;

	return val;

out_err:
	d_fprintf(debug_log, "Unknown var: %s\n", key);
	return "\0";
}

/*
 * Fill out a structure with various environment variables
 * sent to the application.
 */
void set_env_vars(void)
{
	if (fcgx_param("REQUEST_URI"))
		env_vars.request_uri = strdup(fcgx_param("REQUEST_URI"));
	else
		env_vars.request_uri = NULL;

	if (fcgx_param("REQUEST_METHOD"))
		env_vars.request_method = strdup(fcgx_param("REQUEST_METHOD"));
	else
		env_vars.request_method = NULL;

	if (fcgx_param("CONTENT_TYPE"))
		env_vars.content_type = strdup(fcgx_param("CONTENT_TYPE"));
	else
		env_vars.content_type = NULL;

	if (fcgx_param("CONTENT_LENGTH"))
		env_vars.content_length = atoll(fcgx_param("CONTENT_LENGTH"));
	else
		env_vars.content_length = 0;

	if (fcgx_param("HTTP_COOKIE"))
		env_vars.http_cookie = strdup(fcgx_param("HTTP_COOKIE"));
	else
		env_vars.http_cookie = NULL;

	if (fcgx_param("HTTP_USER_AGENT"))
		env_vars.http_user_agent = strdup(fcgx_param(
					"HTTP_USER_AGENT"));
	else
		/*
		 * In case it's (null), we still need at least an empty
		 * string for checking against in is_logged_in()
		 */
		env_vars.http_user_agent = strdup("");

	if (fcgx_param("HTTP_X_FORWARDED_FOR") &&
	    IS_SET(fcgx_param("HTTP_X_FORWARDED_FOR")))
		env_vars.remote_addr = strdup(fcgx_param(
					"HTTP_X_FORWARDED_FOR"));
	else
		env_vars.remote_addr = strdup(fcgx_param("REMOTE_ADDR"));

	if (fcgx_param("HTTP_X_FORWARDED_HOST"))
		env_vars.host = strdup(fcgx_param("HTTP_X_FORWARDED_HOST"));
	else if (fcgx_param("HTTP_HOST"))
		env_vars.host = strdup(fcgx_param("HTTP_HOST"));
	else
		env_vars.host = strdup("");

	if (fcgx_param("REMOTE_PORT"))
		env_vars.remote_port = atoi(fcgx_param("REMOTE_PORT"));
	else
		env_vars.remote_port = 0;

	if (fcgx_param("QUERY_STRING"))
		env_vars.query_string = strdup(fcgx_param("QUERY_STRING"));
	else
		env_vars.query_string = NULL;

	if (fcgx_param("HTTP_REFERER"))
		env_vars.http_referer = strdup(fcgx_param("HTTP_REFERER"));
	else
		env_vars.http_referer = NULL;
}

/*
 * Free's the http environment structure.
 */
void free_env_vars(void)
{
	free(env_vars.request_uri);
	free(env_vars.request_method);
	free(env_vars.content_type);
	free(env_vars.http_cookie);
	free(env_vars.http_user_agent);
	free(env_vars.remote_addr);
	free(env_vars.host);
	free(env_vars.query_string);
	free(env_vars.http_referer);
}

/*
 * Free's the user session structure.
 */
void free_user_session(void)
{
	free(user_session.username);
	free(user_session.name);
	free(user_session.client_id);
}

/*
 * Send an a password reset email to the required user.
 */
void send_reset_password_mail(const char *address, const char *key)
{
	FILE *fp = popen(MAIL_CMD, "w");

	fprintf(fp, "From: %s\r\n", MAIL_FROM);
	fprintf(fp, "Subject: DNSandMX Password Reset Request\r\n");
	fprintf(fp, "To: %s\r\n", address);
	fputs("Content-Type: text/plain; charset=us-ascii\r\n", fp);
	fputs("Content-Transfer-Encoding: 7bit\r\n", fp);
	fputs("\r\n", fp);

	fputs("You have requested to reset your password."
			"\r\n\r\n", fp);
	fputs("If this wasn't you, then just delete and ignore this email."
			"\r\n\r\n", fp);
	fputs("Please goto the below url to reset ypur password."
			"\r\n", fp);
	fputs("Note that this link is valid for 24 hours.\r\n", fp);
	fputs("\r\n", fp);
	fprintf(fp, "https://%s/reset_password/?key=%s\r\n", env_vars.host,
			key);

	pclose(fp);
}

/*
 * Send an IP ACL deactivation email to the required user.
 */
void send_disable_ipacl_mail(const char *address, const char *key)
{
	FILE *fp = popen(MAIL_CMD, "w");

	fprintf(fp, "From: %s\r\n", MAIL_FROM);
	fprintf(fp, "Subject: DNSandMX IP ACL Deactivation Request\r\n");
	fprintf(fp, "To: %s\r\n", address);
	fputs("Content-Type: text/plain; charset=us-ascii\r\n", fp);
	fputs("Content-Transfer-Encoding: 7bit\r\n", fp);
	fputs("\r\n", fp);

	fputs("You have requested to disable your IP ACL."
			"\r\n\r\n", fp);
	fputs("If this wasn't you, then just delete and ignore this email."
			"\r\n\r\n", fp);
	fputs("Please goto the below url to complete this action."
			"\r\n", fp);
	fputs("Note that this link is valid for 24 hours.\r\n", fp);
	fputs("\r\n", fp);
	fprintf(fp, "https://%s/disable_ipacl/?key=%s\r\n", env_vars.host,
			key);

	pclose(fp);
}

/*
 * Send an account activation email to the required user.
 */
void send_activation_mail(const char *address, const char *key)
{
	FILE *fp = popen(MAIL_CMD, "w");

	fprintf(fp, "From: %s\r\n", MAIL_FROM);
	fprintf(fp, "Subject: DNSandMX Account Activation\r\n");
	fprintf(fp, "To: %s\r\n", address);
	fputs("Content-Type: text/plain; charset=us-ascii\r\n", fp);
	fputs("Content-Transfer-Encoding: 7bit\r\n", fp);
	fputs("\r\n", fp);

	fputs("You have requested to sign up for an account with DNSandMX."
			"\r\n\r\n", fp);
	fputs("If this wasn't you, then just delete and ignore this email."
			"\r\n\r\n", fp);
	fputs("Please goto the below url to complete your account setup."
			"\r\n", fp);
	fputs("Note that this activation link is valid for 24 hours.\r\n", fp);
	fputs("\r\n", fp);
	fprintf(fp, "https://%s/activate_account/?key=%s\r\n\r\n\r\n",
			env_vars.host, key);
	fputs("Thank you for choosing DNSandMX.\r\n\r\n", fp);
	fputs("Once your account is activated you can login at\r\n", fp);
	fprintf(fp, "https://%s/login/\r\n\r\n", env_vars.host);
	fputs("You can find useful information at the following\r\n", fp);
	fputs("http://dnsandmx.com/support.html\r\n", fp);
	fprintf(fp, "https://%s/ips_and_hosts/\r\n\r\n", env_vars.host);
	fputs("If you have any problems please drop an email to "
			"support@dnsandmx.com\r\n", fp);
	fputs("You can also try on IRC in #support on irc.dnsandmx.com"
			"\r\n\r\n", fp);
	fputs("DNSandMX.", fp);

	pclose(fp);
}

/*
 * Send a domain expiry warning to the user
 */
void send_expiry_mail(const char *name, const char *address,
		      const char *domain, const char *type, time_t expires)
{
	FILE *fp = popen(MAIL_CMD, "w");
	struct tm *tm = gmtime(&expires);

	fprintf(fp, "From: %s\r\n", MAIL_FROM);
	fprintf(fp, "Subject: DNSandMX service expiry warning for %s\r\n",
			domain);
	fprintf(fp, "To: %s <%s>\r\n", name, address);
	fputs("Content-Type: text/plain; charset=us-ascii\r\n", fp);
	fputs("Content-Transfer-Encoding: 7bit\r\n", fp);
	fputs("\r\n", fp);

	fprintf(fp, "%s,\r\n\r\n", name);
	fprintf(fp, "This message is just to let you know that your %s domain "
			"with DNSandMX\r\n\r\n", type);
	fprintf(fp, "\t%s\r\n\r\n", domain);
	fprintf(fp, "will expire on %04d-%02d-%02d\r\n\r\n",
			tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday);

	fprintf(fp, "If you would like to continue your service beyond its "
			"expiry date,\r\nplease renew your domain for "
			"another year.\r\n\r\n");
	fprintf(fp, "You can renew at any time and your new renew date will "
			"be one year\r\nafter your current expiry date."
			"\r\n\r\n");
	fprintf(fp, "Thank you.\r\n");
	fprintf(fp, "DNSandMX");

	pclose(fp);
}

/*
 * Send a domain expired message to the user
 */
void send_expired_mail(const char *name, const char *address,
		       const char *domain, const char *type, time_t expires)
{
	FILE *fp = popen(MAIL_CMD, "w");
	struct tm *tm = gmtime(&expires);

	fprintf(fp, "From: %s\r\n", MAIL_FROM);
	fprintf(fp, "Subject: DNSandMX service expiry notification for %s\r\n",
			domain);
	fprintf(fp, "To: %s <%s>\r\n", name, address);
	fputs("Content-Type: text/plain; charset=us-ascii\r\n", fp);
	fputs("Content-Transfer-Encoding: 7bit\r\n", fp);
	fputs("\r\n", fp);

	fprintf(fp, "%s,\r\n\r\n", name);
	fprintf(fp, "This message is just to let you know that your %s domain "
			"with DNSandMX\r\n\r\n", type);
	fprintf(fp, "\t%s\r\n\r\n", domain);
	fprintf(fp, "expired on %04d-%02d-%02d\r\n\r\n",
			tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday);

	fprintf(fp, "If you would like to resume your service. All you need "
			"to do is\r\nrenew your domain.\r\n\r\n");
	fprintf(fp, "Thank you.\r\n");
	fprintf(fp, "DNSandMX");

	pclose(fp);
}

/*
 * Hash a given password using either the SHA256 or SHA512 alogorithm.
 */
char *generate_password_hash(int hash_type, const char *password)
{
	static const char salt_chars[64] =
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	char salt[21];
	int i;

	memset(salt, 0, sizeof(salt));

	if (hash_type == SHA256)
		strcpy(salt, "$5$");
	else
		strcpy(salt, "$6$");

	for (i = 3; i < 19; i++) {
		long r;
		struct timespec tp;

		clock_gettime(CLOCK_REALTIME, &tp);
		srandom(tp.tv_sec * tp.tv_nsec);
		r = random() % 64; /* 0 - 63 */
		salt[i] = salt_chars[r];
	}
	strcat(salt, "$");

	return crypt(password, salt);
}

/*
 * Given a user ID, delete their session(s) from the tokyo cabinet
 * session file.
 */
void delete_user_session(unsigned int uid)
{
	char suid[11];
	int i;
	int rsize;
	TCTDB *tdb;
	TDBQRY *qry;
	TCLIST *res;

	tdb = tctdbnew();
	tctdbopen(tdb, SESSION_DB, TDBOWRITER);

	snprintf(suid, sizeof(suid), "%u", uid);
	qry = tctdbqrynew(tdb);
	tctdbqryaddcond(qry, "uid", TDBQCNUMEQ, suid);
	res = tctdbqrysearch(qry);
	for (i = 0; i < tclistnum(res); i++) {
		const char *rbuf = tclistval(res, i, &rsize);
		tctdbout(tdb, rbuf, strlen(rbuf));
	}

	tclistdel(res);
	tctdbqrydel(qry);
	tctdbclose(tdb);
	tctdbdel(tdb);
}

/*
 * Given a username, check if an account for it already exists.
 */
bool user_already_exists(const char *username)
{
	char *user;
	bool ret = false;
	MYSQL_RES *res;

	user = make_mysql_safe_string(username);
	res = sql_query(conn, "SELECT username FROM passwd WHERE username = "
			"'%s'", user);
	if (mysql_num_rows(res) > 0)
		ret = true;

	mysql_free_result(res);
	free(user);

	return ret;
}

/*
 * Calculate the page_number to show and the where in the results
 * set to show from.
 *
 * This is used in the results pagination code.
 */
void get_page_pagination(const char *req_page_no, int rpp, int *page_no,
			 int *from)
{
	*page_no = atoi(req_page_no);

	if (*page_no < 2) {
		/* Reset to values for showing the first page */
		*page_no = 1;
		*from = 0;
	} else {
		*from = *page_no * rpp - rpp;
	}
}

/*
 * Create the next / prev page navigation links.
 */
void do_pagination(TMPL_varlist *varlist, int page, int nr_pages)
{
	if (IS_MULTI_PAGE(nr_pages)) {
		char page_no[12];

		if (!IS_FIRST_PAGE(page)) {
			snprintf(page_no, sizeof(page_no), "%d", page - 1);
			varlist = TMPL_add_var(varlist, "prev_page", page_no,
					(char *)NULL);
		}
		if (!IS_LAST_PAGE(page, nr_pages)) {
			snprintf(page_no, sizeof(page_no), "%d", page + 1);
			varlist = TMPL_add_var(varlist, "next_page", page_no,
					(char *)NULL);
		}
	} else {
		varlist = TMPL_add_var(varlist, "no_pages", "true",
				(char *)NULL);
	}
}

/*
 * Create a zebra list with alternating highlighted rows.
 *
 * If varlist is NULL it returns a _new_ varlist otherwise
 * it returns _the_ varlist.
 */
TMPL_varlist *do_zebra(TMPL_varlist *varlist, unsigned long row)
{
	TMPL_varlist *vlist = NULL;

	if (!(row % 2))
		vlist = TMPL_add_var(varlist, "zebra", "yes", (char *)NULL);
	else
		vlist = TMPL_add_var(varlist, "zebra", "no", (char *)NULL);

	return vlist;
}

/*
 * Simple wrapper around TMPL_add_var()
 */
TMPL_varlist *add_html_var(TMPL_varlist *varlist, const char *name,
			   const char *value)
{
	TMPL_varlist *vlist = NULL;

	vlist = TMPL_add_var(varlist, name, value, (char *)NULL);
	return vlist;
}

/*
 * ctemplate format function to upper case a string
 */
void fmt_str_upper(const char *string, FCGX_Stream *out)
{
	for (; *string != 0; string++)
		fcgx_putc(toupper(*string));
}

/*
 * libctemplate format function for outputting a date in ISO8601 format
 *
 * i.e YYYY-MM-DD
 */
void format_date_utc(const char *value, FCGX_Stream *out)
{
	char buf[11];
	time_t seconds = atoi(value);
	struct tm *tm = gmtime(&seconds);

	snprintf(buf, sizeof(buf), "%04d-%02d-%02d", tm->tm_year + 1900,
			tm->tm_mon + 1, tm->tm_mday);
	fcgx_p(buf);
}

/*
 * libctemplate format function for outputting a date/time in ISO8601 format
 *
 * i.e YYYY-MM-DD HH:MM
 */
void format_datetime_utc(const char *value, FCGX_Stream *out)
{
	char buf[17];
	time_t seconds = atoi(value);
	struct tm *tm = gmtime(&seconds);

	snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d",
			tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
			tm->tm_hour, tm->tm_min);
	fcgx_p(buf);
}

/*
 * Simple anti-xss mechanism.
 *
 * Escape the HTML characters listed here: https://www.owasp.org/index.php/XSS_%28Cross_Site_Scripting%29_Prevention_Cheat_Sheet#RULE_.231_-_HTML_Escape_Before_Inserting_Untrusted_Data_into_HTML_Element_Content
 *
 * This is run as an output filter in libctemplate.
 *
 * We don't use TMPL_encode_entity from libctemplate, as we do some
 * different things and it saves messing with the external library.
 *
 * I'm taking the, 'Be generous in what you accept, but strict in
 * what you send.', philosophy.
 */
void de_xss(const char *value, FCGX_Stream *out)
{
	for (; *value != 0; value++) {
		switch (*value) {
		case '&':
			fcgx_puts("&amp;");
			break;
		case '<':
			fcgx_puts("&lt;");
			break;
		case '>':
			fcgx_puts("&gt;");
			break;
		case '"':
			fcgx_puts("&quot;");
			break;
		case '\'':
			fcgx_puts("&#x27;");
			break;
		case '/':
			fcgx_puts("&#x2F;");
			break;
		default:
			fcgx_putc(*value);
			break;
		}
	}
}

#define STR_ALLOC_SZ	512
/*
 * A function similar to de_xss, but returns a dynamically allocated
 * string that must be free'd.
 */
char *xss_safe_string(const char *string)
{
	char *safe_string = malloc(STR_ALLOC_SZ);
	size_t alloc = STR_ALLOC_SZ;

	safe_string[0] = '\0';
	for (; *string != '\0'; string++) {
		if (strlen(safe_string) + 7 > alloc) {
			safe_string = realloc(safe_string,
					alloc + STR_ALLOC_SZ);
			if (!safe_string)
				goto out_fail;
			alloc += STR_ALLOC_SZ;
		}
		switch (*string) {
		case '&':
			strcat(safe_string, "&amp;");
			break;
		case '<':
			strcat(safe_string, "&lt;");
			break;
		case '>':
			strcat(safe_string, "&gt;");
			break;
		case '"':
			strcat(safe_string, "&quot;");
			break;
		case '\'':
			strcat(safe_string, "&#x27;");
			break;
		case '/':
			strcat(safe_string, "&#x2F;");
			break;
		default:
			strncat(safe_string, string, 1);
		}
	}

	return safe_string;

out_fail:
	d_fprintf(error_log, "Could not realloc(). Exiting.\n");
	_exit(EXIT_FAILURE);
}

/*
 * Send the specified template to the user.
 */
void send_template(const char *template, TMPL_varlist *varlist,
		   TMPL_fmtlist *fmtlist)
{
	/*
	 * Add the user's name and last login to the template varlist, except
	 * for pages where there is no user session or the /logout/ page.
	 */
	if (user_session.name && !strstr(env_vars.request_uri, "/logout/")) {
		varlist = add_html_var(varlist, "banner_user",
				user_session.name);
		display_last_login(varlist, true);
	}

	fcgx_p("Content-Type: text/html\r\n\r\n");
	TMPL_write(template, NULL, fmtlist, varlist, fcgx_out, error_log);
	fflush(error_log);
}
