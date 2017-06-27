#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(46847);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2015/04/23 21:35:39 $");

  script_cve_id("CVE-2010-1256");
  script_bugtraq_id(40573);
  script_osvdb_id(65216);
  script_xref(name:"IAVB", value:"2010-B-0045");
  script_xref(name:"MSFT", value:"MS10-040");

  script_name(english:"MS10-040: Vulnerability in Internet Information Services Could Allow Remote Code Execution (982666)");
  script_summary(english:"Checks version of Authsspi.dll/Httpapi.dll");

  script_set_attribute(attribute:"synopsis", value:"The remote web server may allow remote code execution.");
  script_set_attribute(attribute:"description", value:
"A remote code execution vulnerability exists in Internet Information
Services (IIS). The vulnerability, which requires that the Extended
Protection for Authentication feature be installed and enabled, is due
to improper parsing of authentication information. An attacker who
successfully exploited this vulnerability could execute code in the
context of the Worker Process Identity (WPI).");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-040");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2003, Vista, 2008,
2008 R2 and 7.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/09");

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
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS10-040';
kbs = make_list("982666", "KB973917");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2003:'2', vista:'1,2', win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

if (hotfix_check_iis_installed() <= 0) audit(AUDIT_NOT_INST, "IIS");

# Check if Extended Protection for Authentication is installed.
epa_installed = FALSE;

# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

hcf_init = TRUE;

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, 'IPC$');
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

# Check whether it's installed.
path = NULL;

key1 = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Hotfix";
key2 = "SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages"; # vista

win_ver = get_kb_item_or_exit("SMB/WindowsVersion");
if(win_ver == "5.2") # 2k3
{
  key1_h = RegOpenKey(handle:hklm, key:key1, mode:MAXIMUM_ALLOWED);
  if (!isnull(key1_h))
  {
    info = RegQueryInfoKey(handle:key1_h);
    for (i=0; i<info[1]; ++i)
    {
      subkey = RegEnumKey(handle:key1_h, index:i);
      pat = "^KB973917(-v[0-9])?";

      if (strlen(subkey) && ereg(pattern:pat, string:subkey))
      {
        epa_installed = TRUE;
        break;
      }
    }

    RegCloseKey(handle:key1_h);
  }
}

if (win_ver == "6.0") # vista
{

  key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
  if (!isnull(key2_h))
  {
    info = RegQueryInfoKey(handle:key2_h);
    for (i=0; i<info[1]; ++i)
    {
      subkey = RegEnumKey(handle:key2_h, index:i);
      kb = "KB973917";

      if (strlen(subkey) && kb >< subkey)
      {
        epa_installed = TRUE;
        break;
      }
    }

    RegCloseKey(handle:key2_h);
  }
}

RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

if (win_ver == "6.1") epa_installed = TRUE;

if (epa_installed != TRUE) exit(0, "Extended Protection for Authentication for IIS is not installed.");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

kb = '982666';
if (
  # Windows 7
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Authsspi.dll", version:"7.5.7600.16576", min_version:"7.5.7600.0", dir:"\system32\inetsrv", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Authsspi.dll", version:"7.5.7600.20694", min_version:"7.5.7600.20000", dir:"\system32\inetsrv", bulletin:bulletin, kb:kb) ||

  # Windows Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Authsspi.dll", version:"7.0.6001.18247", min_version:"7.0.6001.0", dir:"\system32\inetsrv", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Authsspi.dll", version:"7.0.6002.18462", min_version:"7.0.6002.0", dir:"\system32\inetsrv", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Authsspi.dll", version:"7.0.6001.22675", min_version:"7.0.6001.22000", dir:"\system32\inetsrv", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Authsspi.dll", version:"7.0.6002.22388", min_version:"7.0.6002.22000", dir:"\system32\inetsrv", bulletin:bulletin, kb:kb) ||

  # Windows 2003
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Httpapi.dll", version:"5.2.3790.4693", dir:"\system32")
)
{
  set_kb_item(name:"SMB/Missing/MS10-040", value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
