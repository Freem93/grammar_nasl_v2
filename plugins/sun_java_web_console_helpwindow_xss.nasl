#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39590);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/05/17 17:13:10 $");

  script_cve_id("CVE-2009-2283");
  script_bugtraq_id(35513);
  script_osvdb_id(55518, 95342);
  script_xref(name:"Secunia", value:"35597");

  script_name(english:"Sun Java Web Console helpwindow.jsp / masthead.jsp Multiple XSS");
  script_summary(english:"Attempts a non-persistent XSS attack");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application has multiple cross-site scripting
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Sun Java Web Console running on the remote host has
multiple cross-site scripting vulnerabilities in 'helpwindow.jsp' and
'masthead.jsp'.  A remote attacker could exploit these to trick a user
into executing arbitrary HTML or script code in the context of the web
server.");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1020659.1.html");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch referenced in the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value: "2009/06/26");
  script_set_attribute(attribute:"patch_publication_date", value: "2009/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value: "2009/07/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value: "cpe:/a:sun:java_web_console");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("cross_site_scripting.nasl");
  script_require_ports("Services/www", 6789);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");



port = get_http_port(default:6789, no_xss: 1);

unreserved = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.!~*()-]/?=&";
args = make_list("windowTitle", "helpFile", "pageTitle", "mastheadUrl", "mastheadDescription", "jspPath");
cgis = make_list('/console/faces/com_sun_web_ui/help/masthead.jsp', '/console/faces/com_sun_web_ui/help/helpwindow.jsp');
report = '';

foreach cgi ( cgis )
foreach arg ( args )
{
 xss = string(arg, "=</title><script>alert('", SCRIPT_NAME, "')</script>");
 encoded_xss = urlencode(str:xss, unreserved:unreserved);
 expected_output = string(
  "(class=.TtlTxt.>|InfoImage. src=.|<title>|theadDescription=&pageTitle=|/console/html/en/help/|masthead.jsp\\?mastheadUrl=|mastheadDescription=|<frame src=.)</title><script>alert\\('",
  SCRIPT_NAME,
  "'\\)</script>"
 );

 url = string(cgi, '?', encoded_xss);
 res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail: 1);

 if (egrep(string:res[2], pattern:expected_output, icase:TRUE))
 {

  rep = extract_pattern_from_resp(pattern:"RI:" + expected_output, string:res[2]);
  report += string(
      "\n",
      "The argument '" + arg + "' in " , cgi, ":\n\n",
      "  ", build_url(port:port, qs:url), "\n\n",
      "Produced the following response :\n", rep);
 }
 if (!get_kb_item("Settings/PCI_DSS") ) break;
}

if ( strlen(report) > 0 )
{
 set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
 security_warning(port:port, extra:'The following arguments are vulnerable to a XSS:\n' + report);
}

else
 exit(0, 'The web application on port '+port+' does not appear to be vulnerable.');
