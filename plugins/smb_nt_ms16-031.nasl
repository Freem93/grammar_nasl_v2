#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89754);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/07/18 20:50:58 $");

  script_cve_id("CVE-2016-0087");
  script_bugtraq_id(84032);
  script_osvdb_id(135535);
  script_xref(name:"MSFT", value:"MS16-031");

  script_name(english:"MS16-031: Security Update for Microsoft Windows to Address Elevation of Privilege (3140410)");
  script_summary(english:"Checks the file version of Ntdll.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by an elevation of privilege
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by an elevation of privilege vulnerability due to
a failure to properly sanitize handles in memory. An authenticated,
remote attacker can exploit this, via a specially crafted application,
to gain elevated privileges, allowing the execution of arbitrary code
as System.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/security/MS16-031");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
and 2008 R2");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS16-031';

kbs = make_list('3140410');
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1') <= 0)
  audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Ntdll.dll", version:"6.1.7601.23349", min_version:"6.1.7601.20000", dir:"\system32", bulletin:bulletin, kb:"3140410") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Ntdll.dll", version:"6.1.7601.19160", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:"3140410") ||

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Ntdll.dll", version:"6.0.6002.23910", min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:"3140410") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Ntdll.dll", version:"6.0.6002.19598", min_version:"6.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:"3140410")
)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
