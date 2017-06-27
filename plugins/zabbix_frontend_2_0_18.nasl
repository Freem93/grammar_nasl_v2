#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91349);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/08/16 14:42:22 $");

  script_cve_id("CVE-2016-4338");
  script_bugtraq_id(89631);
  script_osvdb_id(137941);
  script_xref(name:"EDB-ID", value:"39769");
  script_xref(name:"IAVB", value:"2016-B-0095");

  script_name(english:"Zabbix < 2.0.18 / 2.2.13 / 3.0.3 'mysql.size' Parameter Command Injection");
  script_summary(english:"Checks Zabbix version");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application is affected by a command injection
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Zabbix
running on the remote host is affected by a command injection
vulnerability due to improper sanitization of user-supplied input to
the 'mysql.size' user parameter. An unauthenticated, remote attacker
can exploit this to inject arbitrary shell commands.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.zabbix.com/browse/ZBX-10741");
  script_set_attribute(attribute:"see_also", value:"http://www.zabbix.com/rn2.0.18.php");
  script_set_attribute(attribute:"see_also", value:"http://www.zabbix.com/rn2.2.13.php");
  script_set_attribute(attribute:"see_also", value:"http://www.zabbix.com/rn3.0.3.php");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Zabbix version 2.0.18 / 2.2.13 / 3.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zabbix:zabbix");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

if (ver =~ "^2\.0\.(([0-9]|1[0-7])(rc[0-9]+)?($|[^0-9]))")
  fix = "2.0.18";

else if (ver =~ "2\.2\.(([0-9]|1[0-2])(rc[0-9]+)?($|[^0-9]))")
  fix = "2.2.13";

else if (ver =~ "3\.0\.([0-2](rc[0-9]+)?($|[^0-9]))")
  fix = "3.0.3";

if (!isnull(fix))
{
  report =
    '\n  URL               : ' + install_url +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "Zabbix", install_url, ver);
