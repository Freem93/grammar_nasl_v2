#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72770);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/09/12 23:24:20 $");

  script_cve_id("CVE-2013-5572", "CVE-2014-1682", "CVE-2014-1685");
  script_bugtraq_id(65402, 65446);
  script_osvdb_id(97811, 102879, 103251);

  script_name(english:"Zabbix < 1.8.20 / 2.0.11 / 2.2.2 Multiple Vulnerabilities");
  script_summary(english:"Checks Zabbix version");

  script_set_attribute(attribute:"synopsis", value:"The remote web application may be affected by multiple vulnerabilities.");
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the instance of Zabbix
listening on the remote host is potentially affected by the following
vulnerabilities :

  - An error exists related to LDAP authentication that
    could disclose the LDAP bind password. (CVE-2013-5572)

  - An error exists related to HTTP authentication, the API
    function 'user.login' call and user switching that could
    allow a security bypass. (CVE-2014-1682)

  - An error exists related to the user type 'Zabbix Admin'
    that could allow unauthorized application changes that
    should be reserved only for the user type 'Zabbix Super
    Admin'. (CVE-2014-1685)

Note that Nessus has not tested for thes issues but has instead relied
only the version in the Zabbix login page."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zabbix.com/rn1.8.20.php");
  script_set_attribute(attribute:"see_also", value:"http://www.zabbix.com/rn2.0.11.php");
  script_set_attribute(attribute:"see_also", value:"http://www.zabbix.com/rn2.2.2.php");
  script_set_attribute(attribute:"see_also", value:"https://support.zabbix.com/browse/ZBX-6721");
  script_set_attribute(attribute:"see_also", value:"https://support.zabbix.com/browse/ZBX-7693");
  script_set_attribute(attribute:"see_also", value:"https://support.zabbix.com/browse/ZBX-7703");
  script_set_attribute(attribute:"solution", value:"Update Zabbix to version 1.8.20, 2.0.11, 2.2.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zabbix:zabbix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

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

if (
  (ver =~ "^1\.8\." && ver_compare(ver:ver, fix:'1.8.20', strict:FALSE) < 0) ||
  (ver =~ "^2\.0\." && ver_compare(ver:ver, fix:'2.0.11', strict:FALSE) < 0) ||
  (ver =~ "^2\.2\." && ver_compare(ver:ver, fix:'2.2.2' , strict:FALSE) < 0)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : 1.8.20 / 2.0.11 / 2.2.2' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "Zabbix", install_url, ver);
