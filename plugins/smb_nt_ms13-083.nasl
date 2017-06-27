#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70335);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/04/23 21:44:06 $");

  script_cve_id("CVE-2013-3195");
  script_bugtraq_id(62801);
  script_osvdb_id(98217);
  script_xref(name:"MSFT", value:"MS13-083");
  script_xref(name:"IAVA", value:"2013-A-0189");

  script_name(english:"MS13-083: Vulnerability in Windows Common Control Library Could Allow Remote Code Execution (2864058)");
  script_summary(english:"Checks version of Comctl32.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A library on the remote Windows host has an integer overflow
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has an integer overflow vulnerability in the Windows
Common Control Library.  The vulnerability could allow remote code
execution if an attacker sends a specially crafted web request to an
ASP.NET web application running on an affected system.  An attacker
could exploit this vulnerability without authentication to run arbitrary
code."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-083");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows 2003, XP, Vista,
2008, 7, 2008 R2, 8, 2012, and Server Core installation option."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

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

bulletin = 'MS13-083';
kb = '2864058';

kbs = make_list(kb);
if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

arch = get_kb_item_or_exit('SMB/ARCH');
if (arch != "x64") audit(AUDIT_ARCH_NOT, "x64", arch);

# RT is not affected
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if (("Windows Embedded" >< productname)) exit(0, "The host is running "+productname+" and is, therefore, not affected.");

if (hotfix_check_sp_range(win2003:'2', vista:'2', win7:'1', win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8 / Windows Server 2012
  # x86 and x64
  hotfix_is_vulnerable(os:"6.2", sp:0, arch:"x64", file:"Comctl32.dll", version:"5.82.9200.20765", min_version:"5.82.9200.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # x64
  hotfix_is_vulnerable(os:"6.2", sp:0, arch:"x64", file:"Comctl32.dll", version:"5.82.9200.16658", min_version:"5.82.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, arch:"x64", file:"Comctl32.dll", version:"5.82.7601.22376", min_version:"5.82.7601.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, arch:"x64", file:"Comctl32.dll", version:"5.82.7601.18201", min_version:"5.82.7600.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, arch:"x64", file:"Comctl32.dll", version:"5.82.6002.23151", min_version:"5.82.6002.23000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, arch:"x64", file:"Comctl32.dll", version:"5.82.6002.18879", min_version:"5.82.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2003 and XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x64", file:"Comctl32.dll", version:"5.82.3790.5190", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x64", file:"Comctl32.dll", version:"6.0.3790.5190", min_version:"6.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/" + bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
