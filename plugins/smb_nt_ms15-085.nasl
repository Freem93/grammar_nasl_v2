#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85330);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/08/16 04:44:42 $");

  script_cve_id("CVE-2015-1769");
  script_bugtraq_id(76222);
  script_osvdb_id(125993);
  script_xref(name:"MSFT", value:"MS15-085");
  script_xref(name:"IAVA", value:"2015-A-0192");

  script_name(english:"MS15-085: Vulnerability in Mount Manager Could Allow Elevation of Privilege (3082487)");
  script_summary(english:"Checks the version of ntdll.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by an elevation of privilege
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by an elevation of privilege
vulnerability in the Mount Manager component due to improper
processing of symbolic links. A local attacker can exploit this
vulnerability by inserting a malicious USB device into a user's
system, allowing the writing of a malicious binary to disk and the
execution of arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-085");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 8, RT, 2012, 8.1, RT 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

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

bulletin = 'MS15-085';
win10_kb = '3082487';
other_kb = '3071756';

kbs = make_list(win10_kb, other_kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

vuln = 0;

if (
  # Windows 10
  hotfix_is_vulnerable(os:"10", sp:0, file:"ntdll.dll", version:"10.0.10240.16430", min_version:"10.0.10240.16000", dir:"\system32", bulletin:bulletin, kb:win10_kb) ||

  # Windows 8.1 / Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"ntdll.dll", version:"6.3.9600.17936", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:other_kb) ||

  # Windows 8 / Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"ntdll.dll", version:"6.2.9200.17438", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:other_kb) ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"ntdll.dll", version:"6.2.9200.21548", min_version:"6.2.9200.21000", dir:"\system32", bulletin:bulletin, kb:other_kb) ||

  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"ntdll.dll", version:"6.1.7601.18933", min_version:"6.1.7600.18000", dir:"\system32", bulletin:bulletin, kb:other_kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"ntdll.dll", version:"6.1.7601.23136", min_version:"6.1.7601.23000", dir:"\system32", bulletin:bulletin, kb:other_kb) ||

  # Windows Vista SP2 / Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"ntdll.dll", version:"6.0.6002.19454", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:other_kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"ntdll.dll", version:"6.0.6002.23762", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:other_kb)
) vuln++;

if( vuln )
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
