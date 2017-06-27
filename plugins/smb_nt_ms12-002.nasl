#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if (description)
{
  script_id(57470);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/04/23 21:35:41 $");

  script_cve_id("CVE-2012-0009");
  script_bugtraq_id(51297);
  script_osvdb_id(78212);
  script_xref(name:"EDB-ID", value:"18642");
  script_xref(name:"MSFT", value:"MS12-002");
  script_xref(name:"IAVA", value:"2012-A-0006");

  script_name(english:"MS12-002: Vulnerability in Windows Object Packager Could Allow Remote Code Execution (2603381)");
  script_summary(english:"Checks the value of a registry key");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by a remote code execution vulnerability
when handling files with embedded packaged objects. An attacker can
exploit this vulnerability by tricking a user into opening a
legitimate file with an embedded packaged object file that is located
in the same network directory as a specially crafted executable file.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-002");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows XP and 2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS12-002';
kb = '2603381';
kbs = make_list(kb);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

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

vuln = FALSE;

key = "SOFTWARE\Classes\Package\protocol\StdFileEditing\server";

vuln_value =  "packager.exe";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h);
  if (!isnull(item))
  {
    if (vuln_value == tolower(item[1]))
    {
      RegCloseKey(handle:key_h);
      vuln = TRUE;
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
