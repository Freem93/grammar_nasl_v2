#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51875);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/23 20:42:24 $");

  script_name(english:"PRTG Network Monitor Default Credentials");
  script_summary(english:"Tries to login as prtgadmin");

  script_set_attribute(attribute:"synopsis", value:"The remote web application uses default credentials.");
  script_set_attribute(
    attribute:"description",
    value:
"It is possible to log into the remote PRTG Network Monitor installation
by providing the default credentials.  A remote attacker could exploit
this to gain administrative control of the PRTG Network Monitor
installation."
  );
  script_set_attribute(attribute:"solution", value:"Secure the 'prtgadmin' account with a strong password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("prtg_network_monitor_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 80);
  script_require_keys("www/prtg_network_monitor");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


user = 'prtgadmin';
pass = 'prtgadmin';

port = get_http_port(default:80, embedded:TRUE);

install = get_install_from_kb(appname:'prtg_network_monitor', port:port, exit_on_fail:TRUE);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

url = install['dir'];
postdata = 'username='+user+'&password='+pass;
res = http_send_recv3(
  method:'POST',
  item:url + '/public/checklogin.htm',
  data:postdata,
  content_type:'application/x-www-form-urlencoded',
  port:port,
  follow_redirect:2,
  exit_on_fail:TRUE
);

login_url = build_url(qs:url, port:port);

# Look for evidence that the login was successful
if (
  'Logout' >< res[2] &&
  'PRTG System Administrator' >< res[2] &&
  'Sorry! Your login has failed' >!< res[2]
)
{
  if (report_verbosity > 0)
  {
    report = '
Nessus was able to gain access using the following information :

  URL      : '+login_url+'
  User     : '+user+'
  Password : '+pass+'
';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "PRTG Network Monitor", login_url);
