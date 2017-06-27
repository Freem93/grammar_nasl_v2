#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(51173);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2015/04/23 21:35:40 $");

  script_cve_id("CVE-2010-2742");
  script_bugtraq_id(45271);
  script_osvdb_id(69819);

  script_name(english:"MS10-101: Vulnerability in Windows Netlogon Service Could Allow Denial of Service (2207559)");
  script_summary(english:"Checks version of Netlogon.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a denial of service
vulnerability in the Netlogon RPC Service.");

  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of the NetLogon RPC service
that is affected by a denial of service vulnerability.

An attacker with administrative privileges on a machine that is joined
to the same domain as the affected domain controller could cause a
denial of service by sending a specially crafted Netlogon RPC service.");

  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-101");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2003, 2008, and
2008 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/15");

  script_xref(name:"MSFT", value:"MS10-101");
  script_xref(name:"IAVB", value:"2010-B-0109");
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

bulletin = 'MS10-101';
kbs = make_list("2207559");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2003:'2', vista:'1,2', win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
hcf_init = TRUE;
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

# Determine if the server is a domain controller
ad_enabled=FALSE;
key = "SYSTEM\CurrentControlSet\Control\ProductOptions";
item = "ProductType";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
  value = RegQueryValue(handle:key_h, item:item);
  if (!isnull (value) && (value[1] == "LanmanNT"))
    ad_enabled = TRUE;
  RegCloseKey (handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);
if (!ad_enabled) exit(0, "The remote host is not affected because it is not a Domain Controller.");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

kb = "2207559";
if (
  # Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Netlogon.dll", version:"6.1.7600.20787", min_version:"6.1.7600.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Netlogon.dll", version:"6.1.7600.16661", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Netlogon.dll", version:"6.0.6002.22496", min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Netlogon.dll", version:"6.0.6002.18316", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Netlogon.dll", version:"6.0.6001.22769", min_version:"6.0.6001.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Netlogon.dll", version:"6.0.6001.18529", min_version:"6.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2003
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Netlogon.dll", version:"5.2.3790.4760", dir:"\system32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/MS10-101", value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
