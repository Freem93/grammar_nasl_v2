#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91714);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/06/21 16:59:01 $");

  script_osvdb_id(135117);

  script_name(english:"Zabbix < 2.2.12 / 2.4.8 / 3.0.1 charts.php 'stime' Parameter Resource Consumption Remote DoS");
  script_summary(english:"Checks the Zabbix version on login page.");

  script_set_attribute(attribute:"synopsis", value:
"The web application running on the remote host is affected by a denial
of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Zabbix
running on the remote host is affected by a denial of service
vulnerability due to improper sanitization of user-supplied input to
the 'stime' parameter in the 'charts.php' script. A remote attacker
can exploit this issue to consume server resources, resulting in a
denial of service condition.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.zabbix.com/rn2.2.12.php");
  script_set_attribute(attribute:"see_also", value:"http://www.zabbix.com/rn2.4.8.php");
  script_set_attribute(attribute:"see_also", value:"http://www.zabbix.com/rn3.0.1.php");
  script_set_attribute(attribute:"see_also", value:"https://support.zabbix.com/browse/ZBX-10319");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Zabbix version 2.2.12 / 2.4.8 / 3.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zabbix:zabbix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("zabbix_frontend_detect.nasl");
  script_require_keys("installed_sw/zabbix", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "zabbix";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
ver = install['version'];
install_url = build_url(port:port, qs:dir);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

fix = NULL;

if (ver =~ "^2\.2\.(([0-9]|1[01])(rc[0-9]+)?($|[^0-9]))")
  fix = "2.2.12";

else if (ver =~ "^2\.4\.([0-7](rc[0-9]+)?($|[^0-9]))")
  fix = "2.4.8";

else if (ver =~ "^3\.0\.(0(rc[0-9]+)?($|[^0-9]))")
  fix = "3.0.1";

if (!isnull(fix))
{
  report =
    '\n  URL               : ' + install_url +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
  exit(0);
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "Zabbix", install_url, ver);
