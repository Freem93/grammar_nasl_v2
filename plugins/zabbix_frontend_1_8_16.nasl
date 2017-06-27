#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(66945);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/09/12 23:24:20 $");

  script_cve_id("CVE-2013-1364");
  script_bugtraq_id(57471);
  script_osvdb_id(89481);

  script_name(english:"Zabbix < 1.8.16 / 2.0.5 / 2.1.0 user.login cnf Parameter Authentication Bypass");
  script_summary(english:"Checks Zabbix Version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web application may be affected by an authentication bypass
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the instance of Zabbix
listening on the remote host is a version greater than 1.8.1 prior to
1.8.16, or version 2.0.x prior to 2.0.5.  It, therefore, could be
affected by an authentication bypass flaw in the 'user.login' method. 
The issue is triggered when LDAP authentication requests passed via the
'cnf' parameter are not properly handled.  A remote attacker could
override the stored LDAP settings to redirect to authentication. 

Note that Nessus has not tested for these issues but has instead
relied on the version in the Zabbix login page."
  );
  script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/mailarchive/message.php?msg_id=30365329");
  script_set_attribute(attribute:"see_also", value:"https://support.zabbix.com/browse/ZBX-6097");
  script_set_attribute(attribute:"solution", value:"Update Zabbix to version 1.8.16 / 2.0.5 / 2.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zabbix:zabbix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("zabbix_frontend_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/zabbix", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = "Zabbix";
port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(appname:"zabbix", port:port, exit_on_fail:TRUE);

ver = install['ver'];
dir = install['dir'];
install_url = build_url(port:port, qs:dir);

if (ver == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_SERVER_VER, appname, port);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver_split = split(ver, sep:'.', keep:FALSE);
if (ver_split[0] < 2 && max_index(ver_split) < 3) exit(1, appname + " version information is not granular enough to make a determination.");

if (
  ver =~ "^1\.8\.(([2-9]|1[0-5])(rc[0-9]+)?|16rc1)($|[^0-9])" ||
  ver =~ "^2\.0\.[0-4](rc[0-9]+)?($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : 1.8.16 / 2.0.5 / 2.1.0\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, install_url, ver);
