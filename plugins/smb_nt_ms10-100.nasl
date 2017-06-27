#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51172);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/04/23 21:35:40 $");

  script_cve_id("CVE-2010-3961");
  script_bugtraq_id(45318);
  script_osvdb_id(69824);
  script_xref(name:"MSFT", value:"MS10-100");

  script_name(english:"MS10-100: Vulnerability in Consent User Interface Could Allow Elevation of Privilege (2442962)");
  script_summary(english:"Checks the version of Consent.exe");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A Windows component on the remote host is affected by a vulnerability
that could allow escalation of privileges."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Consent User Interface (UI) component of the remote Windows host
does not properly process a registry key that has been set to a
specific value.

An attacker who can log on locally to the affected system and has the
'Impersonate a client after authentication' user right
(SeImpersonatePrivilege) can exploit this to run arbitrary code with
LocalSystem privileges."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-100");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7, and
2008 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
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

bulletin = 'MS10-100';
kbs = make_list("2442962");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'1,2', win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

kb = "2442962";
if (
  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1",       arch:"x64", file:"Consent.exe", version:"6.1.7600.20818", min_version:"6.1.7600.20000", dir:"\SysWOW64", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1",       arch:"x64", file:"Consent.exe", version:"6.1.7600.16688", min_version:"6.1.0.0",        dir:"\SysWOW64", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"6.1",                   file:"Consent.exe", version:"6.1.7600.20818", min_version:"6.1.7600.20000", dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1",                   file:"Consent.exe", version:"6.1.7600.16688", min_version:"6.1.0.0",        dir:"\System32", bulletin:bulletin, kb:kb) ||

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, arch:"x64", file:"Consent.exe", version:"6.0.6002.22506", min_version:"6.0.6002.22000", dir:"\SysWOW64", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, arch:"x64", file:"Consent.exe", version:"6.0.6002.18328", min_version:"6.0.0.0",        dir:"\SysWOW64", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, arch:"x64", file:"Consent.exe", version:"6.0.6001.22778", min_version:"6.0.6001.22000", dir:"\SysWOW64", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, arch:"x64", file:"Consent.exe", version:"6.0.6001.18539", min_version:"6.0.0.0",        dir:"\SysWOW64", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Consent.exe", version:"6.0.6002.22506", min_version:"6.0.6002.22000", dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Consent.exe", version:"6.0.6002.18328", min_version:"6.0.0.0",        dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Consent.exe", version:"6.0.6001.22778", min_version:"6.0.6001.22000", dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Consent.exe", version:"6.0.6001.18539", min_version:"6.0.0.0",        dir:"\System32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/MS10-100", value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
