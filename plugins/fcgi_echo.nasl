#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title (4/28/09)
# - Touch-up on summary (6/9/11)

include("compat.inc");

if (description)
{
 script_id(10838);
 script_version("$Revision: 1.30 $");
 script_cvs_date("$Date: 2017/02/23 16:41:17 $");

 script_osvdb_id(700, 3954);

 script_name(english:"FastCGI Multiple Sample CGI XSS");
 script_summary(english:"Tests for FastCGI samples Cross-Site Scripting");

 script_set_attribute(attribute:"synopsis", value:"The remote web server is prone to cross-site scripting attacks.");
 script_set_attribute(attribute:"description", value:
"Two sample CGI's supplied with FastCGI are vulnerable to cross-site
scripting attacks. FastCGI is an 'open extension to CGI that provides
high performance without the limitations of server specific APIs', and
is included in the default installation of the 'Unbreakable' Oracle9i
Application Server. Various other web servers support the FastCGI
extensions (Zeus, Pi3Web etc).

Two sample CGI's are installed with FastCGI, (echo.exe and echo2.exe
under Windows, echo and echo2 under Unix). Both of these CGI's output
a list of environment variables and PATH information for various
applications. They also display any parameters that were provided to
them.");
 script_set_attribute(attribute:"solution", value:"Always remove sample applications from production servers.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/01/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/01/25");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2002-2017 Matt Moore");
 script_family(english:"CGI abuses : XSS");

 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);
port = get_http_port(default:80);
if ( get_kb_item("www/" + port + "/generic_xss") )
 exit(0, "The web server is vulnerable to XSS.");

if(! get_port_state(port)) exit(0);

# Avoid FP against Compaq Web Management or HTTP proxy
if (get_kb_item('Services/www/'+port+'/embedded')) exit(0);

file = make_list("echo", "echo.exe", "echo2", "echo2.exe");
exploit = string("<script>", SCRIPT_NAME, "</script>");

for (f=0; file[f]; f++)
{
 url = string("/fcgi-bin/", file[f], "?foo=", exploit);
 req = http_get(item:url, port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if ( res == NULL ) exit(0);

 if (exploit >< res)
 {
  if (report_verbosity)
  {
   report = string(
         "\n",
         "The request string used to detect this flaw was :\n",
         "\n",
         "  ", url, "\n",
         "\n",
         "To replicate this manually, try replacing '", SCRIPT_NAME, "'\n",
         "above with either 'document.cookie' or a number such as '123'.\n"
         );

   security_warning(port:port, extra:report);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
  else
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }

  exit(0);
 }
}

