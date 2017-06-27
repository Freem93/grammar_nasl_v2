#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(44422);
 script_version("$Revision: 1.21 $");
 script_cvs_date("$Date: 2016/12/09 21:04:53 $");

 script_cve_id("CVE-2010-0020", "CVE-2010-0021", "CVE-2010-0022", "CVE-2010-0231");
 script_bugtraq_id(38049, 38051, 38054, 38085);
 script_osvdb_id(62253, 62254, 62255, 62256);
 script_xref(name:"MSFT", value:"MS10-012");

 script_name(english:"MS10-012: Vulnerabilities in SMB Could Allow Remote Code Execution (971468)");
 script_summary(english:"Checks version of Srv.sys");

 script_set_attribute(
  attribute:"synopsis",
  value:
"It is possible to execute arbitrary code on the remote Windows host
due to flaws in its SMB implementation."
 );
 script_set_attribute(
  attribute:"description",
  value:
"The remote host is affected by several vulnerabilities in the SMB
server that may allow an attacker to execute arbitrary code or perform
a denial of service against the remote host."
 );
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-012");
 script_set_attribute(
  attribute:"solution",
  value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista, 2008, 7, and 2008 R2."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_cwe_id(20, 94, 264, 310, 362);

 script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/09");
 script_set_attribute(attribute:"patch_publication_date", value:"2010/02/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/09");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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

bulletin = 'MS10-012';
kbs = make_list("971468");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'2', vista:'0,2', win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

kb = "971468";

if (
  # Win7/Win2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Srv.sys", version:"6.1.7600.16481",                               dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Srv.sys", version:"6.1.7600.20591", min_version:"6.1.7600.20000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # Vista/Win2008
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Srv.sys", version:"6.0.6000.16977",                               dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Srv.sys", version:"6.0.6000.21179", min_version:"6.0.6000.20000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Srv.sys", version:"6.0.6001.18381",                               dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Srv.sys", version:"6.0.6001.22581", min_version:"6.0.6001.20000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Srv.sys", version:"6.0.6002.18164",                               dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Srv.sys", version:"6.0.6002.22286", min_version:"6.0.6002.20000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # Win2003 / XP 64
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Srv.sys", version:"5.2.3790.4634",                                dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # WinXP
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Srv.sys", version:"5.1.2600.5923",                                dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, file:"Srv.sys", version:"5.1.2600.3662",                                dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # Win2000
  hotfix_is_vulnerable(os:"5.0",       file:"Srv.sys", version:"5.0.2195.7365",                                dir:"\system32\drivers", bulletin:bulletin, kb:kb)
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
