#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(31037);
 script_version("$Revision: 1.25 $");
 script_cvs_date("$Date: 2015/04/23 21:11:56 $");

 script_cve_id("CVE-2008-0088");
 script_bugtraq_id(27638);
 script_osvdb_id(41461);
 script_xref(name:"MSFT", value:"MS08-003");

 script_name(english:"MS08-003: Vulnerability in Active Directory Could Allow Denial of Service (946538)");
 script_summary(english:"Determines the presence of update 946538.");

 script_set_attribute(attribute:"synopsis", value:"It is possible to crash Active Directory on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote version of Active Directory contains a flaw in the LDAP
request handler code that allows an attacker to crash the remote
Active Directory server.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS08-003");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, Windows XP,
and Windows 2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/02/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/02/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/12");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS08-003';
ad_kb = '943484';
adam_kb = '931374';

kbs = make_list(ad_kb, adam_kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2', win2003:'1,2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# Determine if Active Directory is enabled.
ADAM_Enabled = FALSE;
NTDS_Enabled = FALSE;

# NTDS check
ntds_value = get_registry_value(
  handle:hklm, item:"SYSTEM\CurrentControlSet\Services\NTDS\Parameters\DSA Database file");
if (!isnull(ntds_value))
  NTDS_Enabled = TRUE;

# ADAM check
adam_value = get_registry_value(
  handle:hklm, item:"SYSTEM\CurrentControlSet\Services\ADAM\Performance\Library");
if (!isnull(adam_value))
  ADAM_Enabled = TRUE;

RegCloseKey(handle:hklm);
close_registry(close:FALSE);

if (!NTDS_Enabled && !ADAM_Enabled)
{
  hotfix_check_fversion_end();
  exit(0, "The host is not affected since none of the affected Active Directory products are installed.");
}

if (
  (NTDS_Enabled && hotfix_is_vulnerable(os:"5.2", sp:1, file:"ntdsa.dll", version:"5.2.3790.3043", dir:"\system32", bulletin:bulletin, kb:ad_kb)) ||
  (NTDS_Enabled && hotfix_is_vulnerable(os:"5.2", sp:2, file:"ntdsa.dll", version:"5.2.3790.4188", dir:"\system32", bulletin:bulletin, kb:ad_kb)) ||
  (ADAM_Enabled && hotfix_is_vulnerable(os:"5.2", sp:1, file:"adamdsa.dll", version:"1.1.3790.3043", dir:"\ADAM", bulletin:bulletin, kb:adam_kb)) ||
  (ADAM_Enabled && hotfix_is_vulnerable(os:"5.2", sp:2, file:"adamdsa.dll", version:"1.1.3790.4188", dir:"\ADAM", bulletin:bulletin, kb:adam_kb)) ||

  (ADAM_Enabled && hotfix_is_vulnerable(os:"5.1", sp:2, file:"adamdsa.dll", version:"1.1.3790.4188", dir:"\ADAM", bulletin:bulletin, kb:adam_kb)) ||

  (NTDS_Enabled && hotfix_is_vulnerable(os:"5.0", file:"ntdsa.dll", version:"5.0.2195.7147", dir:"\system32", bulletin:bulletin, kb:ad_kb))
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
