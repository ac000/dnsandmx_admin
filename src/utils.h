/*
 * utils.h
 *
 * Copyright (C) 2012 - 2013	OpenTech Labs
 *				Andrew Clayton <andrew@digital-domain.net>
 *			2013	DNSandMX
 *				Andrew Clayton <andrew@dnsandmx.com>
 *
 * Licensed under the GNU Affero General Public License version 3
 * See AGPL-3.0.txt
 */

#ifndef _UTILS_H_
#define _UTILS_H_

/* Pagination macro's */
#define IS_MULTI_PAGE(nr_pages)		(((nr_pages) > 1) ? 1 : 0)
#define IS_FIRST_PAGE(page)		(((page) == 1) ? 1 : 0)
#define IS_LAST_PAGE(page, nr_pages)	(((page) == (nr_pages)) ? 1 : 0)

void make_fqdn(const char *host, const char *domain, char *buf, size_t sz);
char *hostmaster_to_email(const char *hostmaster, char *email);
char *email_to_hostmaster(const char *email, char *hostmaster);
char *dotchomp(char *string);
bool is_reverse_zone(const char *domain);
bool is_valid_ipv6_addr(const char *addr);
bool is_valid_ipv4_addr(const char *addr);
bool is_valid_hostname(const char *hostname);
bool is_valid_email_address(const char *email_addr);
bool is_domain_editable(int domain_id, const char *table);
char *get_tenant(const char *host, char *tenant);
char *username_to_name(const char *username);
char *generate_hash(char *hash, int type);
void free_avars(void);
void free_vars(GHashTable *vars);
void free_u_files(void);
void set_vars(const char *pbuf);
GHashTable *get_dbrow(MYSQL_RES *res);
const char *get_avar(int index, const char *key);
const char *get_var(GHashTable *vars, const char *key);
void free_env_vars(void);
void free_user_session(void);
void set_env_vars(void);
void send_reset_password_mail(const char *address, const char *key);
void send_activation_mail(const char *address, const char *key);
void send_expiry_mail(const char *name, const char *address,
		      const char *domain, const char *type, time_t expires);
void send_expired_mail(const char *name, const char *address,
		       const char *domain, const char *type, time_t expires);
char *generate_password_hash(int hash_type, const char *password);
void delete_user_session(unsigned int uid);
bool user_already_exists(const char *username);
void get_page_pagination(const char *req_page_no, int rpp, int *page_no,
			 int *from);
void do_pagination(TMPL_varlist *varlist, int page, int nr_pages);
TMPL_varlist *do_zebra(TMPL_varlist *varlist, unsigned long row);
TMPL_varlist *add_html_var(TMPL_varlist *varlist, const char *name,
			   const char *value);
void fmt_str_upper(const char *string, FCGX_Stream *out);
void format_date_utc(const char *value, FCGX_Stream *out);
void format_datetime_utc(const char *value, FCGX_Stream *out);
void de_xss(const char *value, FCGX_Stream *out);
char *xss_safe_string(const char *string);
void send_template(const char *template, TMPL_varlist *varlist,
		   TMPL_fmtlist *fmtlist);

#endif /* _UTILS_H_ */
