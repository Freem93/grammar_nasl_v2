#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64572);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/02/22 15:31:27 $");

  script_cve_id("CVE-2013-0077");
  script_bugtraq_id(57857);
  script_osvdb_id(90128);
  script_xref(name:"MSFT", value:"MS13-011");
  script_xref(name:"IAVA", value:"2013-A-0042");

  script_name(english:"MS13-011: Vulnerability in Media Decompression Could Allow Remote Code Execution (2780091)");
  script_summary(english:"Checks version of Quartz.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host is potentially affected by a code execution
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host is potentially affected by a vulnerability that
could allow remote code execution if a user opens a specially crafted
media file (such as an .mpg file), opens a Microsoft Office document
(such as a .ppt file) that contains a specially crafted embedded media
file, or receives specially crafted streaming content.  An attacker who
successfully exploited this vulnerability could gain the same user
rights as the current user.  Users whose accounts are configured to have
fewer user rights on the system could be less impacted than users who
operate with administrative user rights."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-011");
  script_set_attribute(
    attribute:"solution",
    value:"Microsoft has released a set of patches for XP, 2003, Vista, and 2008."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

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

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS13-011';
kb = '2780091';

kbs = make_list(kb);
if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

# This issue only affects XP, 2003, Vista, and 2008
if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows Embedded" >< productname) exit(0, "The host is running "+productname+" and is not affected.");

# This issue does not affect server core installs
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # XP SP3
  hotfix_is_vulnerable(os:"5.1",             sp:3, file:"Quartz.dll",   version:"6.5.2600.6333",    min_version:"6.5.2600.0",         dir:"\System32", bulletin:bulletin, kb:kb) ||

  # 2003 SP2 & 2003 x64 SP2 & XP Pro x64 SP2
  hotfix_is_vulnerable(os:"5.2",             sp:2, file:"Quartz.dll",   version:"6.5.3790.5105",    min_version:"6.5.3790.0",         dir:"\System32", bulletin:bulletin, kb:kb) ||

  # Vista SP2 & Vista x64 SP2 & 2008 SP2 & 2008 x64 SP2
  hotfix_is_vulnerable(os:"6.0",             sp:2, file:"Quartz.dll",   version:"6.6.6002.18725",   min_version:"6.6.6002.18000",     dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0",             sp:2, file:"Quartz.dll",   version:"6.6.6002.22969",   min_version:"6.6.6002.22000",     dir:"\system32", bulletin:bulletin, kb:kb)
)
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
