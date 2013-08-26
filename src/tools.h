/*
 * tools.h
 *
 *  Copyright (C) 2013		DNSandMX
 *  				Andrew Clayton <andrew@dnsandmx.com>
 *
 * Licensed under the GNU Affero General Public License version 3
 * See AGPL-3.0.txt
 */

#ifndef _TOOLS_H_
#define _TOOLS_H_

void dump_dns_domain_to_bind(int domain_id);
void dump_dns_domain_to_csv(int domain_id);
void dump_mail_fwd_to_csv(int domain_id);

#endif /* _TOOLS_H_ */
