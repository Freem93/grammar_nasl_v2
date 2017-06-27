#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73159);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/24 23:21:20 $");

  script_name(english:"Quantum vmPRO Default Credentials Check");
  script_summary(english:"Tries to login using default credentials");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application that uses a default set
of credentials.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to login to the remote web administration interface of
the Quantum vmPRO appliance using a known set of default credentials.  A
remote attacker using these credentials would have complete control of
the appliance.");
  # http://downloads.quantum.com/quantum_vmPRO_software/3.1/6-67535-04_UsersGuide_vmPRO_RevB.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?59e03804");
  script_set_attribute(attribute:"solution", value:"Change the password for the default sysadmin account.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:quantum:vmpro");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("quantum_vmpro_detect.nbin");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("www/quantum_vmpro");
  script_require_ports("Services/www", 443, 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

port = get_http_port(default:443);

install = get_install_from_kb(
  appname      : "quantum_vmpro",
  port         : port,
  exit_on_fail : TRUE
);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

install_url = build_url(qs:'/', port:port);

# protected API url we can use to test our credentials
info_url = "/managementapi/1/info";

res = http_send_recv3(
  port            : port,
  method          : 'GET',
  item            : info_url,
  username        : 'sysadmin',
  password        : 'sysadmin',
  exit_on_fail    : TRUE
);

if (
  "CherryPy" >< res[1] &&
  res[2] =~ '"product"[ \t]*:[ \t]*"vmPRO"' &&
  '"version"' >< res[2] &&
  '"build"' >< res[2] &&
  "not authorized" >!< res[2]
)
{
  if (report_verbosity > 0)
  {
    report = '\n' + '  Nessus was able to login using the following credentials :\n' +
             '\n' + '    URL      : ' + install_url +
             '\n' + '    Username : sysadmin' +
             '\n' + '    Password : sysadmin\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Quantum vmPRO", install_url);
