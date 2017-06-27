#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49952);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/04/23 21:35:40 $");

  script_cve_id("CVE-2010-3225");
  script_bugtraq_id(43776);
  script_osvdb_id(68550);
  script_xref(name:"IAVA", value:"2010-A-0141");
  script_xref(name:"MSFT", value:"MS10-075");

  script_name(english:"MS10-075: Vulnerability in Media Player Network Sharing Service Could Allow Remote Code Execution (2281679)");
  script_summary(english:"Checks the version of Wmpmde.dll");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to execute arbitrary code on the remote Windows host
using the Microsoft Windows Media Player Network Sharing Service.");
  script_set_attribute(attribute:"description", value:
"A use-after-free vulnerability exists in the Microsoft Windows Media
Player Network Sharing Service installed on the remote host.

By sending a specially crafted Real Time Streaming Protocol (RTSP)
packet to the affected service, a remote attacker may be able to
leverage this vulnerability to execute arbitrary code in the security
context of the Network Service account.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-075");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista and Windows
7.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS10-075';
kbs = make_list("2281679");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'1,2', win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# Determine the Windows product name.
productname = NULL;

port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");


rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"ProductName");
  if (!isnull(item)) productname = item[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel();

if (isnull(productname))
  exit(0, "Failed to determine the Windows product name.");
if ("Windows Vista" >!< productname && "Windows 7" >!< productname)
  exit(0, "The host is running "+productname+" and hence is not affected.");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

kb = "2281679";
if (
  # Windows 7
  hotfix_is_vulnerable(os:"6.1",       file:"Wmpmde.dll", version:"12.0.7600.20787", min_version:"12.0.7600.20000", dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1",       file:"Wmpmde.dll", version:"12.0.7600.16661",                                dir:"\System32", bulletin:bulletin, kb:kb) ||

  # Vista
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Wmpmde.dll", version:"11.0.6002.22471", min_version:"11.0.6002.22000", dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Wmpmde.dll", version:"11.0.6002.18297",                                dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Wmpmde.dll", version:"11.0.6001.7117",  min_version:"11.0.6001.7100",  dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Wmpmde.dll", version:"11.0.6001.7009",                                 dir:"\System32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/MS10-075", value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
