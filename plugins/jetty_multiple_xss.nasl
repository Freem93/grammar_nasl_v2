#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44320);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/10/27 15:03:54 $");

  script_cve_id("CVE-2009-4612");
  script_bugtraq_id(37927);
  script_osvdb_id(61765);
  script_xref(name:"EDB-ID", value:"9887");

  script_name(english:"Mort Bay Jetty Multiple XSS");
  script_summary(english:"Checks for XSS flaws.");

  script_set_attribute(attribute:"synopsis",value:
"The remote web server is affected by multiple cross-site scripting 
flaws.");
  script_set_attribute(attribute:"description", value:
"The remote instance of Mort Bay Jetty web server is affected by
multiple cross-site scripting vulnerabilities.  User-supplied input is
not sanitized at multiple locations, which could allow an
unauthenticated, remote attacker to inject arbitrary HTML or script
code into a user's browser to be executed within the security context
of the affected site.");
  script_set_attribute(attribute:"see_also", value:"http://www.ush.it/team/ush/hack-jetty6x7x/jetty-adv.txt");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2009/Oct/215");

  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mortbay:jetty");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/jetty");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default: 8080);
if (get_kb_item("www/"+port+"/generic_xss"))  exit(0,"Generic XSS KB is already set for port "+ port + ".");

# Unless we're paranoid, make sure the banner looks like Mort Bay Jetty.
#
# nb: the Server Response header can be suppressed; eg, see
#     <http://docs.codehaus.org/display/JETTY/How+to+suppress+the+Server+HTTP+header>.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (!banner) exit(1, "No HTTP banner on port "+port);
  if ("Server: Jetty(" >!< banner) exit(1,"Remote banner on port " + port + " is not from Mort Bay Jetty web server.");
}

# Send a request to exploit the flaw.

xss  = string("<script>alert('",SCRIPT_NAME,"')</script>");

exploit[1] = "jsp/dump.jsp?" + xss;
 result[1] = '<th>getParameter("' + xss ;

exploit[2] = "test/jsp/dump.jsp?" + xss;
 result[2] = '<th>getParameter("' + xss ;

exploit[3] = "jspsnoop/ERROR/" + xss;
 result[3] = '/jspsnoop/ERROR/' + xss + "</TD>";

vuln = 0;
for (i = 1 ; i < 4 ; i++)
{

 vuln = test_cgi_xss(
   port     : port,
   cgi      : exploit[i],
   dirs     : make_list("/"),
   pass_str : result[i],
   pass_re  : "<script>alert"
  );

  if (vuln) exit(0);
  else if (!thorough_tests) break;
}
if (!vuln)
  exit(0, "The instance of Jetty listening on port "+ port + " is not affected.");
