#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96908);
  script_version("$Revision: 1.5 $");
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

  script_name(english:"Cisco WebEx for Internet Explorer RCE (cisco-sa-20170124-webex)");
  script_summary(english:"Checks the extension version.");

  script_set_attribute(attribute:"synopsis", value:
"A browser extension installed on the remote host is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Cisco WebEx Extension for Internet Explorer installed on the
remote host is affected by a remote code execution vulnerability due
to a crafted pattern that permits any URL utilizing it to
automatically use native messaging to access sensitive functionality
provided by the extension. An unauthenticated, remote attacker can
exploit this vulnerability to execute arbitrary code by convincing a
user to visit a web page that contains this pattern and starting a
WebEx session.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170124-webex
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?068aee48");
  script_set_attribute(attribute:"see_also", value:"https://bugs.chromium.org/p/project-zero/issues/detail?id=1096");
  script_set_attribute(attribute:"see_also", value:"https://bugs.chromium.org/p/project-zero/issues/detail?id=1100"); 
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco WebEx Extension version 2.1.0.10 or later.");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:webex");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_reg_query.inc");
include("smb_hotfixes_fcheck.inc");
include("global_settings.inc");

report = "";
ver = NULL;
fix = "2.1.0.10";

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

key = "SOFTWARE\ActiveTouch\Deinstall\NS_Unknown\WebEx\T30_MC\ieatgpc.dll";

path = get_registry_value(handle:hklm, item:key);
RegCloseKey(handle:hklm);
close_registry(close:TRUE);

hotfix_check_fversion_init();

if(!empty_or_null(path))
{
  ver = hotfix_get_fversion(path:path);
}
else
{
  path = hotfix_get_systemroot();
  path = path + "\Downloaded Program Files\ieatgpc.dll";
  ver = hotfix_get_fversion(path:path);
}

hotfix_check_fversion_end();

error = hotfix_handle_error(error_code:ver['error'], file:path, exit_on_fail:TRUE);

ver = ver['value'];
ver = split(ver, sep:",", keep:false);
ver = join(ver, sep:".");

if(ver_compare(ver:ver, fix:fix, strict:FALSE) < 0)
{
  port =  kb_smb_transport();
  if (!port) port = 445;

  report += '\n' +
            'One or more users have a vulnerable version of the Cisco WebEx Extension for Internet Explorer installed: ' +
            '\n' +
            '\n  Installed version : ' + ver +
            '\n  Fixed Version     : ' + fix +
            '\n  Path              : ' + path +
            '\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco WebEx Extension for Internet Explorer");
