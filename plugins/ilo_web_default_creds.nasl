#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72877);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/23 20:31:32 $");

  script_name(english:"HP Integrated Lights-Out (iLO) Default Credentials");
  script_summary(english:"Tries to login in with default credentials");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application is protected using default administrative
credentials."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote HP Integrated Lights-Out (iLO) install uses a default set of
credentials ('Admin' / 'Admin' or 'Oper' / 'Oper') to control access to
its management interface. 

With this information, an attacker can gain access to the application."
  );
  script_set_attribute(attribute:"solution", value:"Log into the application and change the default login credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:integrated_lights-out");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("ilo_detect.nasl");
  script_require_keys("www/ilo");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 443, 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

port = get_http_port(default:443, embedded:TRUE);
generation = get_kb_item("ilo/generation");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# Clear the cookies, in case Nessus was given credentials.
clear_cookiejar();

install = get_install_from_kb(
  appname      : "ilo",
  port         : port,
  exit_on_fail : TRUE
);
dir = install["dir"];
install_url = build_url(port:port, qs:dir);

# iLO 3 and 4 use default passwords provided by vendor and attached
# to the device so only check generation 1 and 2 for these defaults
if (generation =~ "^(3|4)") audit(AUDIT_WEB_APP_NOT_AFFECTED, "HP Integrated Lights-Out (iLO) " + generation, install_url);

logins = make_array("Admin", "Admin", "Oper", "Oper");
success = NULL;

foreach user (keys(logins))
{
  postdata = "loginId="+user+"&password="+logins[user];

  res = http_send_recv3(
    method : "POST",
    item   : dir + "/signin.html",
    port   : port,
    data   : postdata,
    content_type    : "application/x-www-form-urlencoded",
    exit_on_fail    : TRUE
  );

  if (
    (res[0] =~ "200 OK") &&
    (egrep(pattern:'\\<title\\>HP (Integrated Lights-Out|iLO Sign In)',
    string:res[2], icase: TRUE)) &&
    ('http-equiv="refresh" content="0; URL=/home.html' >< res[2])
  )
  {
    success +=
      '  Username : ' + user + '\n' +
      '  Password : ' + logins[user] + '\n\n';
  }
}

if (generation) generation = " " + generation;
if (isnull(success))
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "HP Integrated Lights-Out (iLO)" + generation, build_url(port:port, qs:dir));

if (report_verbosity > 0)
{
  header = 'Nessus was able to gain access using the following URL';
  trailer =
    'and the following credentials :\n' +
    success;

  report = get_vuln_report(
    items   : dir + "/signin.html",
    port    : port,
    header  : header,
    trailer : trailer
  );
  security_hole(port:port, extra:report);
}
else security_hole(port);
