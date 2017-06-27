#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(60081);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/02/08 22:04:49 $");

  script_name(english:"Eaton Network Shutdown Module Default Administrator Credentials");
  script_summary(english:"Tries to login with default admin credentials");

  script_set_attribute(attribute:"synopsis", value:"A web application is using default administrative credentials.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote Eaton Network Shutdown Module install uses a default set of
credentials to control access to its administrative functionality.

With this information, an attacker can gain complete access to the
application."
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Log into the application and set a strong password for the
administrator."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:eaton:network_shutdown_module");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("network_shutdown_module_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("www/eaton_nsm");
  script_require_ports("Services/www", 4679);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");


port = get_http_port(default:4679, embedded:FALSE);


install = get_install_from_kb(appname:"eaton_nsm", port:port, exit_on_fail:TRUE);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

dir = install['dir'];
install_url = build_url(qs:dir, port:port);


# Clear the cookies, in case Nessus was given credentials.
clear_cookiejar();


# Try to log in.
creds = make_array();
creds["admin"] = "admin";
creds["MGEUPS"] = "MGEUPS";

url = dir + '/pane_userscfg.php';
foreach user (keys(creds))
{
  pass = creds[user];

  res = http_send_recv3(
    port         : port,
    method       : 'GET',
    item         : url,
    username     : user,
    password     : pass,
    exit_on_fail : TRUE
  );

  # There's a problem if we've get the content of the page.
  if (
    '<TITLE>Users account' >< res[2] &&
    "'Create new user'" >< res[2]
  )
  {
    if (report_verbosity > 0)
    {
      header = 'Nessus was able to gain access using the following URL';
      trailer =
        'and the following set of credentials :\n' +
        '\n' +
        '  Username : ' + user + '\n' +
        '  Password : ' + pass;

      report = get_vuln_report(items:url, port:port, header:header, trailer:trailer);
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
}

audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Eaton Network Shutdown Module', install_url);
