#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(56174);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/23 21:35:41 $");

  script_cve_id("CVE-2011-1991");
  script_bugtraq_id(47741);
  script_xref(name:"IAVA", value:"2012-A-0002");
  script_osvdb_id(75382);
  script_xref(name:"MSFT", value:"MS11-071");

  script_name(english:"MS11-071: Vulnerability in Windows Components Could Allow Remote Code Execution (2570947)");
  script_summary(english:"Checks for MS11-073");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host is affected by a code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by a code execution vulnerability.
By tricking a user into opening a legitimate rich text file (.rtf),
text file (.txt), or Word document (.doc) that is in the same
directory as a specially crafted library file, a remote,
unauthenticated user could execute arbitrary code on the host subject
to the privileges of the user running the affected component.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-071");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, and 2008 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

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

bulletin = 'MS11-071';
kb = '2570947';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
winver = get_kb_item_or_exit('SMB/WindowsVersion');

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

if (winver == '5.1' || winver == '5.2')
{
  # Connect to the appropriate share.
  port    = kb_smb_transport();
  login   = kb_smb_login();
  pass    = kb_smb_password();
  domain  = kb_smb_domain();

  if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

  hcf_init = TRUE;

  # Connect to the remote registry.
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
  if (winver == '5.1')
  {
    regkeys = make_array(
      'SOFTWARE\\Classes\\CLSID\\{88E729D6-BDC1-11D1-BD2A-00C04FB9603F}\\InProcServer32', '%systemroot%\\system32\\fde.dll',
      'SOFTWARE\\Classes\\CLSID\\{5A8371A3-0C6D-487B-B3C8-46D785C4C940}\\InProcServer32', '%systemroot%\\system32\\eapahost.dll'
    );
  }
  else
  {
    regkeys = make_array(
      'SOFTWARE\\Classes\\CLSID\\{1B53F360-9A1B-1069-930C-00AA0030EBC8}\\InProcServer32', '%systemroot%\\system32\\hypertrm.dll',
      'SOFTWARE\\Classes\\CLSID\\{88895560-9AA2-1069-930E-00AA0030EBC8}\\InProcServer32', '%systemroot%\\system32\\hticons.dll'
    );
  }

  vuln = FALSE;
  foreach key (keys(regkeys))
  {
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h))
    {
      item = RegQueryValue(handle:key_h);
      if (!isnull(item))
      {
        if (item[1] != regkeys[key])
        {
          RegCloseKey(handle:key_h);
          vuln = TRUE;
          break;
        }
      }
      else
      {
        RegCloseKey(handle:key_h);
        RegCloseKey(handle:hklm);
        NetUseDel();
        exit(1, 'Failed to open the registry key '+key+'\n');
      }
      RegCloseKey(handle:key_h);
    }
    else
    {
      RegCloseKey(handle:hklm);
      NetUseDel();
      exit(1, 'Failed to open the registry handle '+key+'\n');
    }
  }
  RegCloseKey(handle:hklm);
  NetUseDel();
  if (vuln)
  {
    set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
    hotfix_add_report(bulletin:bulletin, kb:kb);

    hotfix_security_hole();
    exit(0);
  }
  else audit(AUDIT_HOST_NOT, 'affected');
}

if (!is_accessible_share()) exit(1, 'is_accessible_share() failed.');

if (
  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Imjpapi.dll", version:"10.1.7601.21779", min_version:"10.1.7601.20000", dir:"\system32\IME\IMEJP10", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Imjpapi.dll", version:"10.1.7601.17658", min_version:"10.1.7600.0", dir:"\system32\IME\IMEJP10", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Imjpapi.dll", version:"10.1.7600.21016", min_version:"10.1.7600.20000", dir:"\system32\IME\IMEJP10", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Imjpapi.dll", version:"10.1.7600.16856", min_version:"10.1.7600.0", dir:"\system32\IME\IMEJP10", bulletin:bulletin, kb:kb) ||

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Imjpapi.dll", version:"10.0.6002.22684", min_version:"10.0.6002.20000", dir:"\system32\IME\IMEJP10", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Imjpapi.dll", version:"10.0.6002.18495", min_version:"10.0.6002.0", dir:"\system32\IME\IMEJP10", bulletin:bulletin, kb:kb)
)
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
