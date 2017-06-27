#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(56091);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/04 18:02:24 $");

  script_cve_id("CVE-2011-2904", "CVE-2011-3263", "CVE-2011-3264");
  script_bugtraq_id(49016, 49275, 63920);
  script_osvdb_id(74275, 74665, 74667);

  script_name(english:"Zabbix < 1.8.6 Multiple Vulnerabilities");
  script_summary(english:"Checks Zabbix Version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web application may be affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the instance of Zabbix
listening on the remote host is earlier than 1.8.6.  It could,
therefore, be affected by multiple vulnerabilities. 

  - An input validation error exists in the script
    'acknow.php' that allows arbitrary script or HTML
    injection via the 'backurl' parameter. (CVE-2011-2904)

  - An error exists related to 'zabbix_agentd' and
    'vfs.file.cksum'. An attacker could cause excessive CPU
    usage if the 'vfs.file.cksum' command is pointed at a
    special device such as '/dev/urandom'. (CVE-2011-3263)

  - An information disclosure vulnerability exists in the
    script 'popup.php' because the 'srcfld2' parameter is
    not properly checked. This vulnerability can reveal
    sensitive information such as the application's install
    path. (CVE-2011-3264)

Note that Nessus has not tested for these flaws but has instead relied
on the version in the Zabbix login page."
  );
  # http://web.archive.org/web/20120304113355/http://secnut.blogspot.com/2011/05/zabbix-cross-site-scripting.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ad30fa5c");
  script_set_attribute(attribute:"see_also", value:"https://support.zabbix.com/browse/ZBX-3794");
  script_set_attribute(attribute:"see_also", value:"https://support.zabbix.com/browse/ZBX-3835");
  script_set_attribute(attribute:"see_also", value:"https://support.zabbix.com/browse/ZBX-3840");
  script_set_attribute(attribute:"see_also", value:"http://www.zabbix.com/rn1.9.4.php");
  script_set_attribute(attribute:"solution", value:"Update Zabbix to version 1.8.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/07");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zabbix:zabbix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

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

fix_version = '1.8.6';
if (ver_compare(ver:ver, fix:fix_version, strict:FALSE) < 0)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
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
