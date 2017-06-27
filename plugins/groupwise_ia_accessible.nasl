#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50691);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/10/21 20:34:20 $");

  script_name(english:"Novell GroupWise Internet Agent Accessible");
  script_summary(english:"Tries to access GroupWise Internet Agent Console");

  script_set_attribute(attribute:"synopsis", value:"The remote web server is accessible without authentication.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server is a Novell GroupWise Internet Agent web
console.

By allowing unauthenticated access to this web server, anyone may be
able to read status, configuration, or log files pertaining to GroupWise
Internet Agent, or even restart the agent.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?019e5e6e");
  script_set_attribute(
    attribute:"solution",
    value:
"Consult the GroupWise Administration Guide for information about
restricting access to the GroupWise Internet Agent.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 9850);
  script_require_keys("www/groupwise-ia");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:9850, embedded:TRUE);

banner = get_http_banner(port:port, exit_on_fail:TRUE);

headers = parse_http_headers(status_line:banner, headers:banner);
if (isnull(headers))
  exit(1, 'Error processing HTTP response headers from the web server on port '+port+'.');

server = headers['server'];
if (isnull(server))
  exit(0, "The web server on port "+port+" doesn't send a Server response header.");

if ('GroupWise GWIA' >< server)
{
  set_kb_item(name:"Services/www/"+port+"/embedded", value:TRUE);
  url = "/";

  res = http_get_cache(port:port, item:url);

  if(res =~ '^HTTP/1\\.[01] +401 ')
    exit (0, "Authentication is required to access the remote web server on port "+ port +".");

  # There's a problem if we were able to access the console.
  if (
    " GWIA - "        >< res   &&
    ">GroupWise "     >< res   &&
    ">Configuration<" >< res  &&
    ">Environment<"   >< res  &&
    ">Restart Internet Agent<" >< res
  )
  {
    report = get_vuln_report(items:url, port:port);
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, "The web server on port "+port+" doesn't appear to be from GroupWise GWIA.");
