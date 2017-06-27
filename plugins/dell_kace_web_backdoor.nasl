#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56754);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/10/09 22:45:48 $");

  script_cve_id("CVE-2011-4046");
  script_bugtraq_id(50605);
  script_osvdb_id(76939);
  script_xref(name:"TRA", value:"TRA-2011-11");
  script_xref(name:"CERT", value:"135606");

  script_name(english:"Dell KACE K2000 Web Backdoor Account");
  script_summary(english:"Tries to login as the backdoor user");

  script_set_attribute(
    attribute:"synopsis",
    value:
"It is possible to log into the remote web application by using a
hidden account."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Nessus was able to log into the remote Dell KACE K2000 system using a
hidden account.  The hidden account, 'kbox1248163264128256', also has
administrator privileges.  A remote, unauthenticated attacker could
exploit this issue to gain administrative access to the K2000 device.

After gaining administrator access to the web interface, an attacker
could elevate privileges by exploiting an arbitrary root command
execution vulnerability, but Nessus has not checked for that issue.

Note that this plugin requires that the setting 'Do not log in with
user accounts not specified in the scan policy' be disabled."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2011-11");
  script_set_attribute(attribute:"see_also", value:"http://www.kace.com/support/kb/index.php?action=artikel&id=1120");
  script_set_attribute(attribute:"solution", value:"Upgrade to K2000 3.3 SP1 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:kace_k2000_systems_deployment_appliance");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("dell_kace_web_detect.nasl");
  script_require_keys("www/dell_kace_k2000");
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
install = get_install_from_kb(appname:'dell_kace_k2000', port:port, exit_on_fail:TRUE);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

user = 'kbox1248163264128256';
pass = 'kbox1248163264128256';
url = install['dir'] + '/_login';
postdata =
  'LOGIN_NAME=' + user +
  '&LOGIN_PASSWORD=' + pass +
  '&save=Login';

res = http_send_recv3(
  method:'POST',
  item:url,
  port:port,
  content_type:'application/x-www-form-urlencoded',
  data:postdata,
  follow_redirect:2,
  exit_on_fail:TRUE
);

base_url = build_url(qs:install['dir'], port:port);

if ('Logged in as: ' + user >< res[2])
{
  if (report_verbosity > 0)
  {
    report =
      '\n' + 'Nessus logged in using the following URL and credentials :\n' +
      '\n  URL      : ' + base_url + '/login' +
      '\n  Username : ' + user +
      '\n  Password : ' + pass + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Dell KACE K2000', base_url);
