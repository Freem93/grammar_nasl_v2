#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80084);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/10 22:03:56 $");

  script_name(english:"Visual Mining NetCharts Server Default Credentials (Web UI)");
  script_summary(english:"Attempts to login with default credentials.");

  script_set_attribute(attribute:"synopsis", value:"The remote web application uses default credentials.");
  script_set_attribute(attribute:"description", value:
"It is possible to log into the remote Visual Mining NetCharts Server
installation by providing the default credentials. A remote,
unauthenticated attacker can exploit this to gain administrative
control.");
  script_set_attribute(attribute:"solution", value:
"Contact the vendor to see if patches are available. If patches are
unavailable, restrict access to the web service.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:visual_mining:netcharts_server");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("visual_mining_netcharts_server_web_detect.nbin");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("installed_sw/Visual Mining NetCharts Server");
  script_require_ports("Services/www", 8001);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("http.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

app = "Visual Mining NetCharts Server";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8001);

install = get_single_install(app_name:app, port:port);

creds = make_array(
  "Admin", "Admin",
  "Scheduler", "!@#$scheduler$#@!"
);
url = "/Admin/index.jsp";
full_url = build_url(qs:url, port:port);

report = '';

foreach user (keys(creds))
{
  pass = creds[user];

  res = http_send_recv3(
    method          : "GET",
    item            : url,
    port            : port,
    username        : user,
    password        : pass
  );

  if ("200 OK" >!< res[0] || 'NetCharts Server' >!< res[2])
    continue;

  report +=
    '\n' + 'Nessus was able to login using the following credentials:' +
    '\n' +
    '\n' + '  URL      : ' + full_url +
    '\n' + '  Username : ' + user +
    '\n' + '  Password : ' + pass +
    '\n';
}

if (report == '')
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, full_url);

if (report_verbosity > 0)
  security_hole(port:port, extra:report);
else security_hole(port);
