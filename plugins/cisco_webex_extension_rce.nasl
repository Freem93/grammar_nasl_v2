#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96772);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/02/06 16:27:35 $");

  script_cve_id("CVE-2017-3823");
  script_bugtraq_id(95737);
  script_osvdb_id(150755);
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170124-webex");
  script_xref(name:"IAVA", value:"2017-A-0030");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc86959");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc88194");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc88535");
  script_xref(name:"CERT", value:"909240");

  script_name(english:"Cisco WebEx Extension for Chrome RCE (cisco-sa-20170124-webex)");
  script_summary(english:"Checks the extension version.");

  script_set_attribute(attribute:"synopsis", value:
"A browser extension installed on the remote host is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Cisco WebEx Extension for Chrome installed on the remote host is
affected by a remote code execution vulnerability due to a crafted
pattern that permits any URL utilizing it to automatically use native
messaging to access sensitive functionality provided by the extension.
An unauthenticated, remote attacker can exploit this vulnerability to
execute arbitrary code by convincing a user to visit a web page that
contains this pattern and starting a WebEx session.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170124-webex
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?068aee48");
  script_set_attribute(attribute:"see_also", value:"https://bugs.chromium.org/p/project-zero/issues/detail?id=1096");
  script_set_attribute(attribute:"see_also", value:"https://bugs.chromium.org/p/project-zero/issues/detail?id=1100"); 
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco WebEx Extension version 1.0.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Cisco WebEx Chrome Extension RCE (CVE-2017-3823)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:webex");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("win_chrome_browser_addons.nbin");
  script_require_keys("SMB/Google_Chrome/Installed", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("datetime.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_reg_query.inc");
include("smb_hotfixes_fcheck.inc");
include("browser.inc");
include("json.inc");

addons = get_browser_addons(browser:"Chrome", type:"all", name:"Cisco WebEx Extension", exit_on_fail:TRUE);
ext_report = "";
report = "";
ver = NULL;
vuln = 0;
users = make_array();

hotfix_check_fversion_init();

foreach addon(addons["addons"])
{
  if(users[addon['user']]) continue;

  # Try to get active version from preferences
  path = eregmatch(pattern:"(.*)Extensions.*", string:addon['path']);
  path = path[1] + "Secure Preferences";
  prefs = hotfix_get_file_contents(path:path);

  if(prefs['error'] == 0)
  {
    prefs = json_read(prefs['data']);
    ver = prefs[0]["extensions"]["settings"]["jlhmfgmfgeifomenelglieieghnjghma"]["manifest"]["version"];
    users[addon['user']] = TRUE;
  }

  if(empty_or_null(ver))
  {
    if (report_paranoia < 2)
    {
      hotfix_check_fversion_end();
      audit(AUDIT_PARANOID);
    }
    ver = chomp(addon['version']);
  }

  if(ver_compare(ver:ver, fix:"1.0.7", strict:FALSE) < 0)
  {
    vuln += 1;
    ext_report += '\n' +
                  '\n  User        : ' + addon['user'] +
                  '\n  Version     : ' + addon['version'] +
                  '\n  Update date : ' + addon['update_date'] +
                  '\n  Path        : ' + addon['path'] +
                  '\n';
  }
}

hotfix_check_fversion_end();

if(vuln)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if(vuln > 1) user = "users have";
  else user = "user has";

  report += '\n' +
            "The following " + user + " a vulnerable version of the Cisco WebEx Extension for Chrome installed:" +
            ext_report +
            '\n' +
            "Fix: Upgrade to version 1.0.7 or later." +
            '\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco WebEx Extension for Chrome");
