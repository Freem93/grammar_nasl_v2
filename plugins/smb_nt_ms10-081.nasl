#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(49958);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2015/04/23 21:35:40 $");

  script_cve_id("CVE-2010-2746");
  script_bugtraq_id(43717);
  script_osvdb_id(68549);
  script_xref(name:"EDB-ID", value:"15963");
  script_xref(name:"IAVB", value:"2010-B-0090");
  script_xref(name:"MSFT", value:"MS10-081");

  script_name(english:"MS10-081: Vulnerability in Windows Common Control Library Could Allow Remote Code Execution (2296011)");
  script_summary(english:"Checks version of");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A library on the remote Windows host has a buffer overflow
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a heap-based buffer overflow vulnerability in the
Windows common control library.  This vulnerability can be exploited
when a user visits a specially crafted web page while using a third-
party scalable vector graphics (SVG) viewer.

A remote attacker could exploit this by tricking a user into visiting
a maliciously crafted web page."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-081");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows 2003, XP, Vista,
2008, 7, and 2008 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/13");

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

bulletin = 'MS10-081';
kbs = make_list("2296011");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'1,2', win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

kb = "2296011";
if (
  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Comctl32.dll", version:"6.10.7600.20787", min_version:"6.10.7600.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Comctl32.dll", version:"6.10.7600.16661", min_version:"6.10.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Comctl32.dll", version:"5.82.7600.20787", min_version:"5.82.7600.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Comctl32.dll", version:"5.82.7600.16661", min_version:"5.82.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Comctl32.dll", version:"5.82.6002.22480", min_version:"5.82.6002.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Comctl32.dll", version:"5.82.6002.18305", min_version:"5.82.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Comctl32.dll", version:"5.82.6001.22755", min_version:"5.82.6001.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Comctl32.dll", version:"5.82.6001.18523", min_version:"5.82.6001.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2003 and XP x64
  hotfix_is_vulnerable(os:"5.2",       file:"Comctl32.dll", version:"5.82.3790.4770", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Comctl32.dll", version:"5.82.2900.6028", min_version:"5.82.2900.0000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Comctl32.dll", version:"6.0.2900.6028", min_version:"6.0.2900.0000", dir:"\system32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/MS10-081", value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
