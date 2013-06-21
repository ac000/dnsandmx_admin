#!/bin/sh
#
# Looks at the deferred mail queue and updates the relay_domains table
# with the number of queued messages for each domain
#

user=""
pass=""

export PATH="/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/root/bin"

# Clear the queue_sz values.
mysql -u ${user} -p${pass} postfix -e "UPDATE relay_domains SET queue_sz = 0"

IFS="
"

for line in `qshape -b 1 deferred | tail -n+3 | sed 's/^[ \t]*//'`; do
	IFS=" "
	set -- $line
	mysql -u ${user} -p${pass} postfix -e "UPDATE relay_domains SET queue_sz = $2 WHERE domain = '$1'"
	IFS="
"
done
