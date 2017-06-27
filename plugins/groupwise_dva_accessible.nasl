#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50689);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/10/21 20:34:20 $");

  script_name(english:"Novell GroupWise Document Viewer Agent Web Console Accessible");
  script_summary(english:"Tries to access the DVA Web Console");

  script_set_attribute(attribute:"synopsis", value:"The remote web server console is accessible without authentication.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server is a Novell GroupWise Document Viewer Agent
(DVA) Web Console.  By allowing unauthenticated access to this agent,
anyone may be able read status, configuration or log files pertaining
to the DVA.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3086959d");
  script_set_attribute(
    attribute:"solution",
    value:
"Consult the GroupWise Administration Guide for information about
restricting access to GroupWise Document Viewer Agent.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("http11_detect.nasl");
  script_require_ports("Services/www", 7439, 7440);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

# The remote webserver is not detected by find_service*.nasl.
# It appears it does not respond to GET requests without
# Host header set. So we query each port.

ports = make_list(7439, 7440);

# Call up the default URL.
url = "/";
dir = '';
installs = NULL;

foreach port (ports)
{
  if (!get_port_state(port)) continue;

  banner = get_http_banner(port:port);
  if (banner && "Server: GroupWise-Document-Viewer-Agent/" >!< banner) continue;

  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
  if ("Server: GroupWise-Document-Viewer-Agent/" >< res[1])
  {
    installs = add_install(
      installs:installs,
      dir:dir,
      appname:'groupwise-dva',
      port:port
     );
    set_kb_item(name:"Services/www/"+port+"/embedded", value:TRUE);
    register_service(port:port, ipproto:"tcp", proto:"www");
  }

  if (res[0] =~ '^HTTP/1\\.[01] +401 ')
  exit (0, "Authentication is required to access the remote web server on port "+ port +".");

  # There's a problem if we were able to access the console.
  if (
    res[2] &&
    "GroupWise Document Viewer Agent" >< res[2] &&
    ">Configuration<" >< res[2] &&
    ">Environment<" >< res[2]   &&
    " Document Viewer Agent - " >< res[2]
  )
  {
    if (report_verbosity > 0)
    {
      report = get_vuln_report(items:url, port:port);
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
  }
}
