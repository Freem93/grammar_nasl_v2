#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50693);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/10/21 20:34:20 $");

  script_name(english:"Novell GroupWise WebAccess Accessible");
  script_summary(english:"Tries to access GroupWise WebAccess Console");

  script_set_attribute(attribute:"synopsis", value:"The remote web server is accessible without authentication.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server is a Novell GroupWise WebAccess console.

By allowing unauthenticated access to this web server, anyone may be
able read status, configuration or log files pertaining to GroupWise
WebAccess.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3086959d");
  script_set_attribute(
    attribute:"solution",
    value:
"Consult the GroupWise Administration Guide for information about
restricting access to GroupWise WebAccess.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:groupwise_webaccess");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("http11_detect.nasl");
  script_require_ports("Services/www", 7205, 7211);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

# The remote webserver is not detected by find_service*.nasl.
# It appears the web server does not respond to GET requests without
# Host header set. So we query each port.

ports = make_list(7205, 7211);

# Call up the default URL.
dir = '';
url = "/";
installs = NULL;

foreach port (ports)
{
  if (!get_port_state(port)) continue;

  banner = get_http_banner(port:port);
  if (banner && "Server: GroupWise-WebAccess-Agent/" >!< banner) continue;

  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
  if ("Server: GroupWise-WebAccess-Agent/" >< res[1])
  {
    installs = add_install(
      installs:installs,
      dir:dir,
      appname:'groupwise-webaccess',
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
    "WebAccess -" >< res[2] &&
    ">Configuration<" >< res[2] &&
    ">Environment<" >< res[2]   &&
    ">GroupWise " >< res[2]
    )
    {
      report = get_vuln_report(items:url, port:port);
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
}
