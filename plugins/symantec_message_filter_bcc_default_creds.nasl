#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59835);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/02/10 22:03:56 $");

  script_name(english:"Symantec Message Filter Management Interface Default Credentials");
  script_summary(english:"Tries to login as admin/symantec");

  script_set_attribute(attribute:"synopsis", value:"The remote web application uses default credentials.");
  script_set_attribute(
    attribute:"description",
    value:
"Brightmail Control Center (BCC) is the administrative web interface for
Symantec Message Filter.  It is possible to log into the remote BCC by
providing the default credentials.  A remote attacker could exploit this
to gain administrative control of the application."
  );
  script_set_attribute(attribute:"solution", value:"Secure the admin account with a strong password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date",value:"2012/07/03");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec:message_filter");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("symantec_message_filter_bcc_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("www/smf_bcc");
  script_require_ports("Services/www", 41080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:41080);
install = get_install_from_kb(appname:'smf_bcc', port:port, exit_on_fail:TRUE);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

username = 'admin';
password = 'symantec';
postdata = 'username=' + username +'&password=' + password;
url = install['dir'] + '/login.do';
install_url = build_url(qs:install['dir'], port:port);

res = http_send_recv3(
  method:'POST',
  port:port,
  item:url,
  data:postdata,
  content_type:'application/x-www-form-urlencoded',
  follow_redirect:2,
  exit_on_fail:TRUE
);

if ('Invalid user name or password' >< res[2] || '<a id="anchorLogout" HREF="logoff.do"' >!< res[2])
  audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Symantec Message Filter', install_url);

http_send_recv3(method:'GET', item:install['dir'] + '/logoff.do', port:port);

if (report_verbosity > 0)
{
  report =
    '\nNessus was able to login using the following information :\n' +
    '\n  URL : ' + install_url + url +
    '\n  Username : ' + username +
    '\n  Password : ' + password + '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
