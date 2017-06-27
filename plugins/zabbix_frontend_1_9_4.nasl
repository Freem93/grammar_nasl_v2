#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(71535);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/09/12 23:24:20 $");

  script_cve_id("CVE-2011-3263");
  script_bugtraq_id(63920);
  script_osvdb_id(74667);

  script_name(english:"Zabbix 1.9.x < 1.9.4 zabbix_agentd DoS");
  script_summary(english:"Checks Zabbix version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web application may be affected by a denial of service
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the instance of Zabbix
listening on the remote host is 1.9.x prior to 1.9.4.  It could,
therefore, be affected by a denial of service vulnerability related to
'zabbix_agentd' and 'vfs.file.cksum'.  An attacker can cause excessive
CPU usage if the 'vfs.file.cksum' command is pointed at a special device
such as '/dev/urandom'. 

Note that Nessus has not tested for this issue, but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.zabbix.com/browse/ZBX-3794");
  script_set_attribute(attribute:"see_also", value:"http://www.zabbix.com/rn1.9.4.php");
  script_set_attribute(attribute:"solution", value:"Update Zabbix to version 1.9.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zabbix:zabbix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("zabbix_frontend_detect.nasl");
  script_require_keys("www/zabbix", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);
install = get_install_from_kb(appname:"zabbix", port:port, exit_on_fail:TRUE);

ver = install['ver'];
dir = install['dir'];
install_url = build_url(port:port, qs:dir);

if (ver == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "Zabbix", install_url);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

fix_version = '1.9.4';
if (ver =~ "^1\.9\." && ver_compare(ver:ver, fix:fix_version, strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + ver+
      '\n  Fixed version     : ' + fix_version + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "Zabbix", install_url, ver);
