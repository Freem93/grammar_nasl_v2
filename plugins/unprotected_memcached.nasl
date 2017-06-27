#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(52633);
 script_version ("$Revision: 1.5 $");
 script_cvs_date("$Date: 2013/01/25 01:19:11 $");

 script_name(english: "Unprotected memcached");
 script_summary(english: "Detect memcached on a public address");
 
 script_set_attribute(attribute:"synopsis", value:
"Memcached is running on a public IP address." );
 script_set_attribute(attribute:"description", value:
"Memcached is a memory-based object store. As it is designed for 
performance, this program does not contain any security mechanism 
(ie: authentication), meaning that anyone can connect to this 
server and perform queries against it." );
 script_set_attribute(attribute:"see_also", value:"http://memcached.org/" );
 script_set_attribute(attribute:"see_also", value:"http://www.eu.socialtext.net/memcached/index.cgi" );
 script_set_attribute(attribute:"see_also", value:"http://www.mediawiki.org/wiki/Memcached" );
 script_set_attribute(attribute:"solution", value:
"Make sure that the machine is properly protected by a firewall and
that traffic to the port is restricted to authorized hosts." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"plugin_publication_date", value: "2011/03/11");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO); 
 script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
 script_family(english: "General");
 script_dependencie("memcached_detect.nasl");
 script_require_keys("Services/memcached");
 exit(0);
}

include("global_settings.inc");
include("network_func.inc");
include("misc_func.inc");

if (islocalnet())
 exit(0, "The remote target is on the local network.");
if (is_private_addr())
 exit(0, "The remote target has a private IP address.");

port = get_service(svc:"memcached", exit_on_fail: 1);
security_warning(port: port);
