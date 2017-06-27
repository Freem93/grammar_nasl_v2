#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(34743);
 script_version("$Revision: 1.26 $");
 script_cvs_date("$Date: 2016/12/09 20:55:00 $");

 script_cve_id("CVE-2008-4037");
 script_bugtraq_id(7385);
 script_osvdb_id(49736);
 script_xref(name:"MSFT", value:"MS08-068");

 script_name(english:"MS08-068: Vulnerability in SMB Could Allow Remote Code Execution (957097)");
 script_summary(english:"Determines the presence of update 957097");

 script_set_attribute(attribute:"synopsis", value:"It is possible to execute code on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a version of SMB (Server Message
Block) protocol that is vulnerable to a credentials reflection attack.

An attacker may exploit this flaw to elevate his privileges and gain
control of the remote host.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms08-068");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista and 2008.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'MS08-068 Microsoft Windows SMB Relay Code Execution');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_cwe_id(287);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/11/11");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/11/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/11/12");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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

bulletin = 'MS08-068';
kb = '957097';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'1,2', vista:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Mrxsmb10.sys", version:"6.0.6001.22252", min_version:"6.0.6001.20000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Mrxsmb10.sys", version:"6.0.6001.18130", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Mrxsmb10.sys", version:"6.0.6000.20904", min_version:"6.0.6000.20000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Mrxsmb10.sys", version:"6.0.6000.16738", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mrxsmb.sys", version:"5.2.3790.4369", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:1, file:"Mrxsmb.sys", version:"5.2.3790.3206", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Mrxsmb.sys", version:"5.1.2600.5700", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, file:"Mrxsmb.sys", version:"5.1.2600.3467", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.0",       file:"Mrxsmb.sys", version:"5.0.2195.7174", dir:"\system32\drivers", bulletin:bulletin, kb:kb)
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
