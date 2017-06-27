#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96907);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/03/22 20:48:10 $");

  script_cve_id("CVE-2017-3823");
  script_bugtraq_id(95737);
  script_osvdb_id(150755);
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170124-webex");
  script_xref(name:"IAVA", value:"2017-A-0030");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc86959");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc88194");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc88535");
  script_xref(name:"CERT", value:"909240");

  script_name(english:"Cisco WebEx for Firefox RCE (cisco-sa-20170124-webex)");
  script_summary(english:"Checks the extension version.");

  script_set_attribute(attribute:"synopsis", value:
"A browser extension installed on the remote host is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Cisco WebEx Extension for Firefox installed on the remote host is
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
"Upgrade ActiveTouch General Plugin Container to version 106, or
else upgrade Cisco WebEx Extension to version 1.0.5 or later. However,
if you are using both, then you will need to upgrade both.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Cisco WebEx Chrome Extension RCE (CVE-2017-3823)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:webex");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("win_firefox_browser_addons.nbin");
  script_require_keys("installed_sw/Mozilla Firefox");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("browser.inc");
include("misc_func.inc");
include("global_settings.inc");

get_kb_item_or_exit("installed_sw/Mozilla Firefox");

addons = get_browser_addons(browser:"Firefox", type:"all", name:"all", exit_on_fail:TRUE);
ext_report = "";
report = "";
ver = NULL;
ext = FALSE;
plg = FALSE;
vuln = 0;
paths = make_array();

fix_extension = "1.0.5";
fix_plugin = "106"; # dll file version, corresponds to version 106

foreach addon(addons["addons"])
{
  ver_report = "";

  if(paths[addon['path']]) continue;

  if(addon['name'] == "ActiveTouch General Plugin Container")
  {
    ver_report += '\n  Plugin version : ' + addon['description'] +
                  '\n  File version   : ' + addon['version'];
    fix = fix_plugin;
    ver = chomp(addon['description']);
    ver = pregmatch(pattern:"ActiveTouch General Plugin Container Version (\d+)$", string:ver);
    ver = ver[1];
  }
  else if (addon['name']=="Cisco WebEx Extension")
  {
    ver_report += '\n  Plugin version : ' + addon['name'] +
                  '\n  Version        : ' + addon['version'];
    fix = fix_extension;
    ver = chomp(addon['version']);
  }
  else continue;

  if(empty_or_null(ver)) continue;

  if(ver_compare(ver:ver, fix:fix, strict:FALSE) < 0)
  {
    vuln += 1;
    ext_report += '\n' +
                  '\n  User           : ' + addon['user'] +
                  ver_report +
                  '\n  Update date    : ' + addon['update_date'] +
                  '\n  Path           : ' + addon['path'] +
                  '\n';
    paths[addon['path']] = TRUE;
    if(addon['name'] == "Cisco WebEx Extension") ext = TRUE;
    else if(addon['name'] == "ActiveTouch General Plugin Container") plg = TRUE;
  }
}

fix = NULL;
if(plg && ext) fix = "Fix: Upgrade to version 106 of ActiveTouch General Plugin Container, and 1.0.5 of Cisco WebEx Extension or later.";
else if(plg) fix = "Fix: Upgrade to version 106 of ActiveTouch General Plugin Container or later.";
else if(ext) fix = "Fix: Upgrade to version 1.0.5 of Cisco WebEx Extension or later.";

if(vuln)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if(vuln > 1) user = "users have";
  else user = "user has";

  report += '\n' +
            "The following " + user + " a vulnerable version of the Cisco WebEx Extension or plugin for Firefox installed:" +
            ext_report +
            '\n' +
            fix +
            '\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco WebEx Extension for Firefox");
