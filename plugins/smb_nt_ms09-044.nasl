#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(40565);
 script_version("$Revision: 1.17 $");
 script_cvs_date("$Date: 2015/04/23 21:11:58 $");

 script_cve_id("CVE-2009-1133", "CVE-2009-1929");
 script_bugtraq_id(35971, 35973);
 script_osvdb_id(56911, 56912);
 script_xref(name:"IAVA", value:"2009-A-0071");
 script_xref(name:"MSFT", value:"MS09-044");

 script_name(english:"MS09-044: Vulnerabilities in Remote Desktop Connection Could Allow Remote Code Execution (970927)");
 script_summary(english:"Checks for hotfix 970927");

 script_set_attribute(attribute:"synopsis", value:"It is possible to execute arbitrary code on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Remote Desktop client with
several vulnerabilities that may allow an attacker to execute
arbirtary code on the remote host.

To exploit these vulnerabilities, an attacker would need to lure a
user of the remote host to connect to a rogue RDP server.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS09-044");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista and Server 2008.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);

 script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/11");
 script_set_attribute(attribute:"patch_publication_date", value:"2009/08/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/11");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"stig_severity", value:"II");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS09-044';
kbs = make_list('956744', '958469', '958470', '958471');
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


function win2k_get_path()
{
 local_var login, pass, domain, port, r, hklm;
 local_var key, key_h, value, ret;

 ret = NULL;
 login   = kb_smb_login();
 pass    = kb_smb_password();
 domain  = kb_smb_domain();
 port    = kb_smb_transport();

 if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

 r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
 if (r != 1) audit(AUDIT_SHARE_FAIL, "IPC$");

 hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
 if (isnull(hklm))
 {
  NetUseDel();
  audit(AUDIT_REG_FAIL);
 }

 key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Terminal Server Client";
 key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
 if (!isnull(key_h))
 {
  value = RegQueryValue(handle:key_h, item:"UninstallString");
  if ( ! isnull(value) ) ret = value[1];
  RegCloseKey(handle:key_h);
 }
  RegCloseKey(handle:hklm);
 if ( ! isnull(ret) )
 	ret = ereg_replace(pattern:"\\setup\\Setup\.exe", string:ret, replace:"\");
  return ret;
}

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'2', vista:'0,2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

vuln = 0;

# Windows 2000
if (hotfix_check_sp(win2k:6) > 0)
{
  path = win2k_get_path();
  if ( isnull(path) ) exit(0, "RDP Client not installed.");

  if (hotfix_is_vulnerable(os:"5.0", file:"Mstsc.exe", version:"5.1.2600.3552", path:path, bulletin:bulletin, kb:'958471')) vuln++;
}
else if (
  # MSRDP 6.0 and 6.1
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Mstscax.dll", version:"6.0.6000.16865", dir:"\system32", bulletin:bulletin, kb:'956744') ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Mstscax.dll", version:"6.0.6000.21061", min_version:"6.0.6000.21000", dir:"\system32", bulletin:bulletin, kb:'956744') ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Mstscax.dll", version:"6.0.6001.18266", dir:"\system32", bulletin:bulletin, kb:'956744') ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Mstscax.dll", version:"6.0.6001.22443", min_version:"6.0.6001.22000", dir:"\system32", bulletin:bulletin, kb:'956744') ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mstscax.dll", version:"6.0.6002.18045", dir:"\system32", bulletin:bulletin, kb:'956744') ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mstscax.dll", version:"6.0.6002.22146", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:'956744') ||
  hotfix_is_vulnerable(os:"5.1", file:"Mstscax.dll", version:"6.0.6000.16865", min_version:"6.0.6000.16000", dir:"\system32", bulletin:bulletin, kb:'956744') ||
  hotfix_is_vulnerable(os:"5.1", file:"Mstscax.dll", version:"6.0.6001.18266", min_version:"6.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:'956744') ||
  hotfix_is_vulnerable(os:"5.1", file:"Mstscax.dll", version:"6.0.6002.18045", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:'956744') ||
  hotfix_is_vulnerable(os:"5.2", file:"Mstscax.dll", version:"6.0.6000.16865", min_version:"6.0.6000.16000", dir:"\system32", bulletin:bulletin, kb:'956744') ||
  hotfix_is_vulnerable(os:"5.2", file:"Mstscax.dll", version:"6.0.6001.18266", min_version:"6.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:'956744') ||
  hotfix_is_vulnerable(os:"5.2", file:"Mstscax.dll", version:"6.0.6002.18045", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:'956744') ||
  # MSRDP 5.2
  hotfix_is_vulnerable(os:"5.2", file:"Mstscax.dll",    version:"5.2.3790.4524", min_version:"5.2.0.0", dir:"\system32", bulletin:bulletin, kb:'958469') ||
  hotfix_is_vulnerable(os:"5.1", file:"2k3Mstscax.dll", version:"5.2.3790.4524", min_version:"5.2.0.0", dir:"\system32", bulletin:bulletin, kb:'958469') ||
  # MSRDP 5.1
  hotfix_is_vulnerable(os:"5.1", sp:2, file:"Mstscax.dll", version:"5.1.2600.3581", min_version:"5.1.0.0", dir:"\system32", bulletin:bulletin, kb:'958470')
) vuln++;


if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
