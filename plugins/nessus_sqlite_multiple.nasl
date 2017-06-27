#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88964);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/03/03 17:07:25 $");

  script_cve_id("CVE-2015-5895");
  script_osvdb_id(122105, 122106);

  script_name(english:"Nessus SQLite Multiple RCE");
  script_summary(english:"Checks the version of the web server.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by multiple
remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Nessus
running on the remote host is affected by multiple remote code
execution vulnerabilities in the bundled version of SQLite due to
heap-based buffer overflow conditions in the sqlite3VdbeExec() and
resolve_backslashes() functions. A remote attacker can exploit these
issues to cause a denial of service condition or the execution of
arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2015-05");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Nessus version 5.2.11 / 6.3.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/05/26");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sqlite:sqlite");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nessus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("nessus_detect.nasl");
  script_require_ports("Services/www", 8834);
  script_require_keys("installed_sw/nessus");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("install_func.inc");

get_install_count(app_name:"nessus", exit_if_zero:TRUE);

port = get_http_port(default:8834);

install = get_single_install(app_name:"nessus", port:port, exit_if_unknown_ver:TRUE);
path = install['path'];
install_loc = build_url(port:port, qs:path);

version = install['version'];

if (version =~ "^5\.2\.") # 5.2.0 - 5.2.10
  fix = "5.2.11";
else if (version =~ "^6\.") # 6.0 - 6.3.6
  fix = "6.3.7";
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "Nessus", install_loc, version);

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report = '\n  Installed version : ' + version +
           '\n  Fixed version     : ' + fix + '\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Nessus", install_loc, version);
