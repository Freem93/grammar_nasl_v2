#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(48292);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/04/23 21:35:39 $");

  script_cve_id("CVE-2010-2553");
  script_bugtraq_id(42256);
  script_osvdb_id(66984);
  script_xref(name:"IAVA", value:"2010-A-0103");
  script_xref(name:"MSFT", value:"MS10-055");

  script_name(english:"MS10-055: Vulnerability in Cinepak Codec Could Allow Remote Code Execution (982665)");
  script_summary(english:"Checks version of iccvid.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A media codec on the remote Windows host has a code execution
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Cinepak codec on the remote host has an unspecified code
execution vulnerability.  A remote attacker could exploit this by
tricking a user into opening a specially crafted media file, resulting
in arbitrary code execution."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-055");
  script_set_attribute(
    attribute:"solution",
    value:"Micorosft has released a set of patches for Windows XP, Vista, and 7."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/11");

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

bulletin = 'MS10-055';
kbs = make_list("982665");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'1,2', win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

if("Vista" >!< productname && "XP" >!< productname)
  exit(0, "The host is running "+productname+" and hence is not affected.");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

kb = '982665';

if (
  # Windows 7
  hotfix_is_vulnerable(os:"6.1", arch:"x86", file:"Iccvid.dll", version:"1.10.0.13", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", arch:"x64", file:"Iccvid.dll", version:"1.10.0.13", dir:"\SysWOW64", bulletin:bulletin, kb:kb) ||

  # Vista
  hotfix_is_vulnerable(os:"6.0", arch:"x86", file:"Iccvid.dll", version:"1.10.0.13", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", arch:"x64", file:"Iccvid.dll", version:"1.10.0.13", dir:"\SysWOW64", bulletin:bulletin, kb:kb) ||

  # Windows 2003 (erroneously mentioned in KB982665?) / XP x64
  # The KB says this file is called Wiccvid.dll, but on my XP 64-bit box it's iccvid.dll.
  # We'll check both to be on the safe side
  hotfix_is_vulnerable(os:"5.2", arch:"x64", file:"Wiccvid.dll", version:"1.10.0.13", dir:"\SysWOW64", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", arch:"x64", file:"Iccvid.dll", version:"1.10.0.13", dir:"\SysWOW64", bulletin:bulletin, kb:kb) ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Iccvid.dll", version:"1.10.0.13", dir:"\system32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:'SMB/Missing/MS10-055', value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
