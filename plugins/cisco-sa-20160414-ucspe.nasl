#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91960);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/08/01 15:11:42 $");

  script_cve_id("CVE-2016-1339", "CVE-2016-1340");
  script_osvdb_id(137175, 137176);
  script_xref(name:"TRA", value:"TRA-2016-08");
  script_xref(name:"CISCO-BUG-ID", value:"CSCux68832");
  script_xref(name:"CISCO-BUG-ID", value:"CSCux68837");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160414-ucspe1");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160414-ucspe2");

  script_name(english:"Cisco UCS Platform Emulator < 3.1(1ePE1) Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Cisco UCS Platform Emulator.");

  script_set_attribute(attribute:"synopsis", value:
"The Cisco UCS Platform Emulator running on the remote host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Cisco Unified
Computing System (UCS) Platform Emulator running on the remote host is
prior to 3.1(1ePE1). It is, therefore, affected by the following
vulnerabilities :

  - A command injection vulnerability exists due to improper
    validation of user-supplied input when handling
    ucspe-copy command-line arguments. A local attacker can
    exploit this, via crafted command line arguments, to
    execute arbitrary commands on the system.
    (CVE-2016-1339)

  - An overflow condition exists that is triggered due to
    improper validation of user-supplied input when handling
    libclimeta.so filename arguments. A local attacker can
    exploit this, via crafted filename arguments, to cause a
    denial of service condition or the execution of
    arbitrary code. (CVE-2016-1340)
    
Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160414-ucspe1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d6bfddf7");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160414-ucspe2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5f46674a");
  script_set_attribute(attribute:"see_also", value:"http://www.tenable.com/security/research/tra-2016-08");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco UCS Platform Emulator version 3.1(1ePE1) or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_computing_system_platform_emulator");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_ucs_pe_webui_detect.nbin");
  script_require_keys("installed_sw/Cisco UCS Platform Emulator");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Cisco UCS Platform Emulator";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir     = install['path'];
version = install['version'];

install_url = build_url(port:port, qs:dir);

if (
  version =~ "^[0-2]\." ||
  version =~ "^3\.0\(" ||
  version =~ "^3\.1\([0-9][a-d]PE" ||
  version =~ "^3\.1\(1ePE0\)"
)
{
  report =
    '\n  URL               : ' + install_url +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 3.1(1ePE1)' +
    '\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
