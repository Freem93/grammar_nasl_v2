#
# (C) Tenable Network Security, Inc.
#
#

include("compat.inc");

if (description)
{
 script_id(10475);
 script_version("$Revision: 1.31 $");
 script_cvs_date("$Date: 2016/11/03 14:16:36 $");

 script_cve_id("CVE-2000-0622");
 script_bugtraq_id(1487);
 script_osvdb_id(374);

 script_name(english:"WebSite Pro webfind.exe keywords Parameter Remote Overflow");
 script_summary(english:"Buffer overflow attempt");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is affected by a
buffer overflow flaw.");
 script_set_attribute(attribute:"description", value:
"The 'webfind.exe' CGI script on the remote host is vulnerable to a
buffer overflow when given a too long 'keywords' argument. This
problem allows an attacker to execute arbitrary code as root on this
host.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Jul/268");
 script_set_attribute(attribute:"solution", value:"Upgrade to WebSite Professional 2.5 or delete this CGI.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/07/19");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/07/22");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 # This test is harmless
 script_category(ACT_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/websitepro", "Settings/ParanoidReport");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);


port = get_http_port(default:80);

foreach dir (cgi_dirs())
{
req = string(dir, "/webfind.exe?keywords=", crap(10));
w = http_send_recv3(method:"GET", item:req, port:port);
if (isnull(w)) exit(0);
if (ereg(pattern:"^HTTP/[0-9]\.[0-9] 500 ", string:w[0]))
{
 # No keep alive here
 req = string(dir, "/webfind.exe?keywords=", crap(2000));
 rq = http_mk_get_req(item:req, port:port);
 req = http_mk_buffer_from_req(req: rq);

 soc = http_open_socket(port);
 if(!soc)exit(0);
 send(socket:soc, data:req);
 r = recv_line(socket: soc, length: 64);
 http_close_socket(soc);
 if(!r)security_hole(port);
 }
}
