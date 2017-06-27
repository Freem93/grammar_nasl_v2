#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35649);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/23 20:42:25 $");

  script_name(english:"Trend Micro InterScan Web Security Suite Default Credentials");
  script_summary(english:"Attempts to login with default credentials");

  script_set_attribute(attribute:"synopsis", value:"The remote web application can be accessed with default credentials.");
  script_set_attribute(attribute:"description", value:
"Trend Micro InterScan Web Security Suite is installed on the remote
host.  It is possible to log into the web management interface using
default credentials.");
  # http://www.trendmicro.com/us/enterprise/network-security/interscan-web-security/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dc4cc287");
  script_set_attribute(attribute:"solution", value:
"Refer to the documentation for instructions about changing the default
password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/12");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:trend_micro:interscan_web_security_suite");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl","iwss_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 1812);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:1812,embedded:TRUE);
get_kb_item_or_exit("Services/www/"+port+"/iwss");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# Send a login POST request.
url = "/logon.jsp";
login = "admin";
password = "adminIWSS85";
install_url = build_url(qs:url, port:port);

res = http_send_recv3(
  method:"POST",
  item:"/uilogonsubmit.jsp",
  port:port,
  add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
  data:"wherefrom=summary_scan&uid="+login+"&passwd="+password,
  exit_on_fail:TRUE
);

if ('summary_scan' >< res[1])
{
  # Double check by sending a request to a page that definitely
  # requires credentials.

  res = http_send_recv3(method:"GET", item:"/index.jsp?summary_scan", port:port, exit_on_fail:TRUE);
  if ("system_dashboard.jsp" >< res[2])
  {
    if (report_verbosity > 0)
    {
      report =
        '\n' +
        'Nessus could log into the web management interface using the \n' +
        'following  credentials :\n' +
        '\n' +
        'User     : ' + login + '\n' +
        'Password : ' + password +'\n' +
        'URL      : ' + install_url;
      security_hole(port:port,extra:report);
    }
    else security_hole(port);
    exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "Trend Micro InterScan Web Security Suite", install_url);
