#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67215);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/01/28 22:37:18 $");

  script_cve_id("CVE-2013-3154");
  script_bugtraq_id(60981);
  script_osvdb_id(94987);
  script_xref(name:"MSFT", value:"MS13-058");
  script_xref(name:"IAVA", value:"2013-A-0137");

  script_name(english:"MS13-058: Vulnerability in Windows Defender Could Allow Elevation of Privilege (2847927)");
  script_summary(english:"Checks version of mpclient.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a privilege escalation vulnerability.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a version of Windows Defender installed that is
affected by a privilege escalation vulnerability.  An attacker with
valid login credentials who successfully exploits this vulnerability
can execute arbitrary code with SYSTEM privileges."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-058");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a patch for Windows 7 / Server 2008 R2.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:windows_defender");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS13-058';
kb = '2847927';

kbs = make_list(kb);
if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

# Windows 7 SP 1, 2008 R2 SP1
if (hotfix_check_sp_range(win7:'1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

path = hotfix_get_programfilesdir() + "\Windows Defender";

share = hotfix_path2share(path:path);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
dll_path = get_registry_value(handle:hklm, item:"SYSTEM\CurrentControlSet\Services\WinDefend\Parameters\ServiceDll");
RegCloseKey(handle:hklm);
close_registry();

if (isnull(dll_path)) audit(AUDIT_NOT_INST, "Windows Defender");

if (
  hotfix_is_vulnerable(os:"6.1", file:"Mpclient.dll", version:"6.1.7600.17316", min_version:"6.1.7600.16000", path:path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", file:"Mpclient.dll", version:"6.1.7600.21531", min_version:"6.1.7600.20000", path:path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", file:"Mpclient.dll", version:"6.1.7601.18170", min_version:"6.1.7601.17000", path:path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", file:"Mpclient.dll", version:"6.1.7601.22341", min_version:"6.1.7601.21000", path:path, bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
