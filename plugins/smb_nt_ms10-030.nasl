#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(46312);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2015/04/23 21:11:58 $");

  script_cve_id("CVE-2010-0816");
  script_bugtraq_id(39927);
  script_osvdb_id(64530);
  script_xref(name:"IAVB", value:"2010-B-0039");
  script_xref(name:"MSFT", value:"MS10-030");

  script_name(english:"MS10-030: Vulnerability in Outlook Express and Windows Mail Could Allow Remote Code Execution (978542)");
  script_summary(english:"Checks version of Inetcomm.dll");

  script_set_attribute(attribute:"synopsis", value:
"An integer overflow vulnerability is present on the remote host due
to an issue in Outlook Express / Windows Mail.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Outlook Express /
Windows Mail that contains a flaw that could be used to cause an
integer overflow, resulting in remote code execution.

To exploit this flaw, an attacker would need a victim to connect to a
mail server under their control and send malicious responses to the
victim's email client.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-030");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Outlook Express and
Windows Mail.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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

bulletin = 'MS10-030';
kbs = make_list("978542");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'2', vista:'1,2', win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

kb = '978542';
if (
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Inetcomm.dll", version:"6.1.7600.16543", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Inetcomm.dll", version:"6.1.7600.20659", min_version:"6.1.7600.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Inetcomm.dll", version:"6.0.6001.18416", min_version:"6.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Inetcomm.dll", version:"6.0.6001.22621", min_version:"6.0.6001.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Inetcomm.dll", version:"6.0.6002.18197", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Inetcomm.dll", version:"6.0.6002.22325", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Inetcomm.dll", version:"6.0.3790.4657", dir:"\system32", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.1", sp:2, file:"Inetcomm.dll", version:"6.0.2900.3664", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Inetcomm.dll", version:"6.0.2900.5931", dir:"\system32", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.0",       file:"Inetcomm.dll", version:"6.0.2800.2001", min_version:"6.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0",       file:"Inetcomm.dll", version:"5.50.5010.200",                        dir:"\system32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/MS10-030", value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
