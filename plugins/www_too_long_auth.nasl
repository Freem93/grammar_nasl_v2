#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      This is more of a generic test script.  One vulnerable server is AOL 3.0
#      http://online.securityfocus.com/archive/1/209681

include("compat.inc");

if (description)
{
 script_id(10515);
 script_version("$Revision: 1.31 $");
 script_cvs_date("$Date: 2014/05/27 00:36:24 $");

 script_name(english:"Web Server HTTP Authorization Header Remote Overflow");
 script_summary(english:"Web server authorization buffer overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web server with a remote buffer overflow
vulnerability.");
 script_set_attribute(attribute:"description", value:
"It may be possible to make the web server crash or execute arbitrary
code by sending it an authorization string which is too long.");
 script_set_attribute(attribute:"solution", value:"Upgrade to the latest version.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value:"2000/09/16");

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

 script_copyright(english:"This script is Copyright (C) 2000-2014 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencie("http_version.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www",80);

 exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, embedded: 1);

if (http_is_dead(port: port))exit(1, "The web server on port "+port+" is dead.");

r = http_send_recv3(port: port, method: "GET", item: "/",
  add_headers: make_array("Authorization", strcat("Basic ", crap(2048))));

if (http_is_dead(port: port, retry: 3)) security_hole(port);
