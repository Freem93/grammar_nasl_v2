#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70497);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/02/27 14:36:08 $");

  script_cve_id("CVE-2013-5743");
  script_bugtraq_id(62794);
  script_osvdb_id(98115, 98116);

  script_name(english:"Zabbix < 1.8.18rc1 / 2.0.9rc1 / 2.1.7 Multiple SQL Injections");
  script_summary(english:"Checks Zabbix Version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web application may be affected by multiple SQL injection
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the instance of Zabbix
listening on the remote host is a version prior to 1.8.18rc1 / 2.0.9rc1
/ 2.1.7.  It is, therefore, potentially affected by multiple SQL
injection vulnerabilities.  The following API methods and parameters are
reportedly affected :

  - alert.get            parameters : time_from, time_till
  - event.get            parameters : object, source, eventid_from, eventid_till
  - graphitem.get        parameter  : type
  - graph.get            parameters : type
  - graphprototype.get   parameter  : type
  - history.get          parameters : time_from, time_till
  - trigger.get          parameters : lastChangeSince, lastChangeTill, min_severity
  - triggerprototype.get parameter  : min_severity
  - usergroup.get        parameter  : status

Additionally, code used to add objects such as graphs or maps to
favorites is reportedly also affected by SQL injection attacks.  The
'Dashboard', 'Graphs', 'Maps', 'Latest data', and 'Screens' pages in the
'Monitoring' section are reported to be affected. 

Note that Nessus has not tested for these issues but has instead
relied on the version in the Zabbix login page."
  );
  # https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20131004-0_Zabbix_SQL_injection_v10.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1161f5f6");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/528982/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://support.zabbix.com/browse/ZBX-7091");
  script_set_attribute(attribute:"solution", value:"Update Zabbix to version 1.8.18rc1 / 2.0.9rc1 / 2.1.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Zabbix httpmon.php SQL Injection");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
script_set_attribute(attribute:"metasploit_name", value:'Zabbix 2.0.8 SQL Injection and Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zabbix:zabbix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

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
if (max_index(ver_split) < 3) audit(AUDIT_VER_NOT_GRANULAR, appname, port, ver);

# nb : The advisory notes that all versions prior to the patched
# 1.8.18rc1 / 2.0.9rc1 / 2.1.7 are affected
if (
  ver_split[0] < 1 || 
  (ver_split[0] == 1 && ver_split[1] < 8) ||
  ver =~ "^1\.8\.(([0-9]|1[0-7])(rc[0-9]+)?($|[^0-9]))" ||
  ver =~ "^2\.0\.[0-8](rc[0-9]+)?($|[^0-9])" ||
  ver =~ "^2\.1\.[0-6](rc[0-9]+)?($|[^0-9])"
)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : 1.8.18rc1 / 2.0.9rc1 / 2.1.7\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url, ver);
