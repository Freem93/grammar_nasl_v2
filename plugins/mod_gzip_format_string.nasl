#
# (C) Tenable Network Security, Inc.
#
#
# Ref:
#  From: "Matthew Murphy" <mattmurphy@kc.rr.com>
#  To: "BugTraq" <bugtraq@securityfocus.com>, 
#  Subject: Mod_gzip Debug Mode Vulnerabilities
#  Date: Sun, 1 Jun 2003 15:10:13 -0500



include("compat.inc");

if(description)
{
 script_id(11686);
 script_version("$Revision: 1.19 $");
 script_cvs_date("$Date: 2016/10/27 15:03:55 $");
 script_cve_id("CVE-2003-0843");
 script_osvdb_id(10508);
 
 script_name(english:"mod_gzip Debug Mode mod_gzip_printf Remote Format String");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to a format string attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running mod_gzip with debug symbols compiled in. 
The debug code includes vulnerabilities that can be exploited by an
attacker to gain a shell on this host." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2003/Jun/24" );
 script_set_attribute(attribute:"solution", value:
"If you do not use this module, disable it completely, or recompile it
without the debug symbols." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/06/01");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


 script_summary(english:"mod_gzip detection");
 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl", "find_service1.nasl", "httpver.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

rq = http_mk_get_req(item:"/index.html", port:port,
  add_headers: make_array("Accept-Encoding", "gzip, deflate"));
# The original script removed the User-Agent field, for whatever reason...
rq['User-Agent'] = NULL;

w = http_send_recv_req(port: port, req: rq);
if (isnull(w)) exit(1, "the web server did not answer");


if ("Content-Encoding: gzip" >!< w[1]) exit(0);

if(safe_checks())
{
  # Avoid FP...
  res = w[1];
  if ("Apache" >!< res || "mod_gzip" >!< res)exit(0);
  
  report = string(
    "\n",
    "Note that Nessus could not verify whether mod_gzip has the debug\n",
    "symbols enabled because safe checks were enabled. As a result,\n",
    "this may be a false-positive.\n"
  );
  security_warning(port:port, extra:report);
  exit(0);
}
 
if (report_paranoia < 2) exit(0);

rq = http_mk_get_req(item:"/nessus.html?nn", port:port,
   add_headers: make_array("Accept-Encoding", "gzip, deflate"));
rq['User-Agent'] = NULL;

w = http_send_recv_req(port: port, req: rq);
if (isnull(w)) exit(1, "the web server did not answer");

rq = http_mk_get_req(item:"/nessus.html?%n", port:port, 
    add_headers: make_array("Accept-Encoding", "gzip, deflate"));
rq['User-Agent'] = NULL;
w = http_send_recv_req(port: port, req: rq);
# Even more unreliable than the old version!
if (isnull(w)) security_warning(port);
