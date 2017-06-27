#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70166);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/24 13:12:21 $");

  script_cve_id("CVE-2013-5486", "CVE-2013-5487", "CVE-2013-5490");
  script_bugtraq_id(62483, 62484, 62485);
  script_osvdb_id(97425, 97426, 97427, 97428);
  script_xref(name:"CERT", value:"632656");
  script_xref(name:"IAVB", value:"2013-B-0107");
  script_xref(name:"CISCO-BUG-ID", value:"CSCud80148");
  script_xref(name:"CISCO-BUG-ID", value:"CSCue77029");
  script_xref(name:"CISCO-BUG-ID", value:"CSCue77035");
  script_xref(name:"CISCO-BUG-ID", value:"CSCue77036");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130918-dcnm");

  script_name(english:"Cisco Prime Data Center Network Manager < 6.2(1) Multiple Vulnerabilities (uncredentialed check)");
  script_summary(english:"Checks DCNM version number");

  script_set_attribute(attribute:"synopsis", value:
"A network management system on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Cisco
Prime Data Center Network Manager (DCNM) installed on the remote host
is affected by multiple vulnerabilities :

  - Multiple remote command execution vulnerabilities exist
    in the DCNM-SAN Server component. (CVE-2013-5486)

  - An information disclosure vulnerability exists in the
    DCMN-SAN Server component that could allow an attacker
    to view arbitrary files on the system. (CVE-2013-5487)

  - A XML external entity injection vulnerability exists
    that could allow an attacker to access arbitrary text
    files on the system with root privileges.
    (CVE-2013-5490)

This plugin determines if DCNM is vulnerable by checking the version
number displayed in the web interface. The web interface is not
available in older versions of DCNM.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-254/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-255/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-256/");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130918-dcnm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cdbea5b4");
  script_set_attribute(attribute:"solution", value:"Upgrade to Cisco Prime Data Center Network Manager 6.2(1) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Cisco Prime Data Center Network Manager Arbitrary File Upload');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_data_center_network_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_prime_dcnm_web_detect.nasl");
  script_require_keys("installed_sw/cisco_dcnm_web");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

appname = "Cisco Prime DCNM";
app_id  = "cisco_dcnm_web";
get_install_count(app_name:app_id, exit_if_zero:TRUE);

port = get_http_port(default:80);
install = get_single_install(app_name:app_id, port:port, exit_if_unknown_ver:TRUE);

url = build_url(qs:install['path'], port:port);
ver = install['version'];

match = eregmatch(string:ver, pattern:"^([0-9.]+)\(([^)]+)\)");
if (isnull(match)) exit(1, "Failed to parse the version ("+ver+").");

major = match[1];
build = match[2];

if (
  ver_compare(ver:major, fix:'6.2', strict:FALSE) > 0 ||  # < 6.2.x
  (major == '6.2' && build !~ '^0([^0-9]|$)') # 6.2.x < 6.2(1)
) audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url, ver);

if (report_verbosity > 0)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : 6.2(1)\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
