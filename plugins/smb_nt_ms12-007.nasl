#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57475);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/07/01 20:31:47 $");

  script_cve_id("CVE-2012-0007");
  script_bugtraq_id(51291);
  script_osvdb_id(78208);
  script_xref(name:"MSFT", value:"MS12-007");
  script_xref(name:"IAVB", value:"2012-B-0003");

  script_name(english:"MS12-007: Vulnerability in AntiXSS Library Could Allow Information Disclosure (2607664)");
  script_summary(english:"Checks DisplayVersion in registry");

  script_set_attribute(attribute:"synopsis", value:
"A library is installed on the remote host that is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of the Anti-Cross-Site
Scripting Library (AntiXSS) that is affected by an information
disclosure vulnerability.

An attacker could gain access to sensitive information if he could
pass a malicious script to a website using the sanitization function
of the Anti-Cross-Site Scripting Library.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/521307/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-007");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a new version of the AntiXSS Library.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:anti-cross_site_scripting_library");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');
get_kb_item_or_exit('SMB/Registry/Uninstall/Enumerated');

bulletin = 'MS12-007';
kbs = make_list('2607664');

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (isnull(list)) exit(1, "The 'SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall' KB items are missing.");

installstring = NULL;
foreach name (keys(list))
{
  prod = list[name];
  if (prod && 'Microsoft AntiXSS' >< prod)
  {
    installstring = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(SOFTWARE\/Microsoft\/Windows\/CurrentVersion\/Uninstall\/.+)\/DisplayName$", replace:"\1", string:name);
    installstring = str_replace(find:"/", replace:"\", string:installstring);
  }
}
if (isnull(installstring)) exit(0, "No evidence of AntiXSS was found in the registry.");

# Connect to the appropriate share.
port     = kb_smb_transport();
login    = kb_smb_login();
pass     = kb_smb_password();
domain   = kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
}

# Determine where it's installed.
version = NULL;
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
key_h = RegOpenKey(handle:hklm, key:installstring, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:'DisplayVersion');
  if (!isnull(item)) version = item[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(version))
{
  NetUseDel();
  exit(1, 'The Microsoft AntiXSS version could not be found in the registry.');
}
NetUseDel();

ver = split(version, sep:'.');
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] == 3 ||
   (ver[0] == 4 && ver[1] < 2) ||
   (ver[0] == 4 && ver[1] == 2 && ver[2] < 1))
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 4.2.1\n';
  hotfix_add_report(report, bulletin:bulletin, kb:'2607664');

  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_warning();

  exit(0);
}
else exit(0, 'The Microsoft AntiXSS ' + version + ' install is not affected.');
