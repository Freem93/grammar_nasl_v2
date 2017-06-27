#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67018);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/11 20:19:26 $");

  script_name(english:"GroundWork Monitor Enterprise Default Credentials");
  script_summary(english:"Checks for default credentials");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a web application installed that uses a known set
of default credentials."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a version of GroundWork Monitor Enterprise
installed that is protected by a known set of default credentials."
  );
  script_set_attribute(attribute:"solution", value:"Change the default admin password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gwos:groundwork_monitor");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("groundwork_monitor_enterprise_detect.nasl");
  script_require_keys("www/groundwork_monitor_enterprise");
  script_require_ports("Services/www", 80);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);
appname = "GroundWork Monitor Enterprise";

install = get_install_from_kb(appname:"groundwork_monitor_enterprise", port:port, exit_on_fail:TRUE);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

dir = install['dir'];
location = build_url(qs:dir, port:port);

referer = build_url(qs:'/josso/signon/usernamePasswordLogin.do', port:port);
postdata = "josso_cmd=login&josso_username=admin&josso_password=admin";
res = http_send_recv3(
                      port: port,
                      item: '/josso/signon/usernamePasswordLogin.do',
                      method: 'POST',
                      add_headers: make_array("Referer", referer,
                                              "Content-Type", "application/x-www-form-urlencoded"),
                      data: postdata
                      );

if (
  "You have been successfully authenticated" >< res[2] &&
  "User Information" >< res[2]
)
{
  if (report_verbosity > 0)
  {
    header = 'Nessus was able to gain access using the following URL';
    trailer =
      'and the following set of credentials :' +
      '\n' +
      '\n  Username : admin' +
      '\n  Password : admin' +
      '\n';

    report = get_vuln_report(items:'/portal', port:port, header:header, trailer:trailer);
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, location);
