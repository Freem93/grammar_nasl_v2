#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71314);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/19 18:02:19 $");

  script_cve_id("CVE-2013-5056");
  script_bugtraq_id(64082);
  script_osvdb_id(100766);
  script_xref(name:"MSFT", value:"MS13-099");
  script_xref(name:"IAVA", value:"2013-A-0228");

  script_name(english:"MS13-099: Vulnerability in Microsoft Scripting Runtime Object Library Could Allow Remote Code Execution (2909158)");
  script_summary(english:"Checks the file version of scrrun.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a version of Microsoft Windows that is
affected by a remote code execution vulnerability in the Microsoft
Scripting Runtime Object Library.  An attacker could craft a malicious
website designed to exploit this vulnerability via components of
Internet Explorer.  An attacker could then trick a user into visiting a
website or opening an email attachment containing the crafted
exploit.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-099");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, 2008 R2, 8, 2012, 8.1 and 2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS13-099';
kb58 = '2892074';
kb57 = '2892075';
kb56 = '2892076';

kbs = make_list(kb58, kb57, kb56);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # 8.1 / 2012 R2
  # Windows Script 5.8
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"scrrun.dll", version:"5.8.9600.16429", dir:"\system32", bulletin:bulletin, kb:kb58) ||

  # 8.0 / 2012
  # Windows Script 5.8
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"scrrun.dll", version:"5.8.9200.20845", min_version:"5.8.9200.20000", dir:"\system32", bulletin:bulletin, kb:kb58) ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"scrrun.dll", version:"5.8.9200.16734", min_version:"5.8.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb58) ||

  # 7 / 2008 R2
  # Windows Script 5.8
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"scrrun.dll", version:"5.8.7601.22480", min_version:"5.8.7601.22000", dir:"\system32", bulletin:bulletin, kb:kb58) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"scrrun.dll", version:"5.8.7601.18283", min_version:"5.8.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb58) ||

  # Vista / 2008
  # Windows Script 5.7
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"scrrun.dll", version:"5.7.6002.23242", min_version:"5.7.6002.23000", dir:"\system32", bulletin:bulletin, kb:kb57) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"scrrun.dll", version:"5.7.6002.18960", min_version:"5.7.0.18000", dir:"\system32", bulletin:bulletin, kb:kb57) ||

  # 2003 / XP-64
  # Windows Script 5.7
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"scrrun.dll", version:"5.7.6002.18960", min_version:"5.7", dir:"\system32", bulletin:bulletin, kb:kb57) ||
  # Windows Script 5.6
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"scrrun.dll", version:"5.6.0.8851", dir:"\system32", bulletin:bulletin, kb:kb56) ||

  # XP
  # Windows Script 5.7
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"scrrun.dll", version:"5.7.6002.18960", min_version:"5.7", dir:"\system32", bulletin:bulletin, kb:kb57) ||
  # Windows Script 5.6
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"scrrun.dll", version:"5.6.0.8851", dir:"\system32", bulletin:bulletin, kb:kb56)
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
