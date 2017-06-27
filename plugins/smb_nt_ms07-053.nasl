#
# Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(26018);
 script_version("$Revision: 1.25 $");
 script_cvs_date("$Date: 2015/05/07 12:06:03 $");

 script_cve_id("CVE-2007-3036");
 script_bugtraq_id(25620);
 script_osvdb_id(36935);
 script_xref(name:"MSFT", value:"MS07-053");
 script_xref(name:"CERT", value:"768440");

 script_name(english:"MS07-053: Vulnerability in Windows Services for UNIX Could Allow Elevation of Privilege (939778)");
 script_summary(english:"Determines the version of Services for UNIX");

 script_set_attribute(attribute:"synopsis", value:"A local user can elevate his privileges.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the Windows Services for UNIX
that is vulnerable to a local privileges elevation due to a flaw in
different setuid binary files.

An attacker may use this to elevate his privileges on this host.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS07-053");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Services fo UNIX
3.0, 3.5 and 4.0.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(264);

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/09/11");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/09/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/11");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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

bulletin = 'MS07-053';
kb = '939778';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2', win2003:'1,2', vista:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  (hotfix_check_fversion(path:rootfile, file:"system32\posix.exe", version:"7.0.1701.46", min_version:"7.0.0.0", bulletin:bulletin, kb:kb) == HCF_OLDER) ||
  (hotfix_check_fversion(path:rootfile, file:"system32\posix.exe", version:"8.0.1969.58", min_version:"8.0.0.0", bulletin:bulletin, kb:kb) == HCF_OLDER) ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"posix.exe", version:"6.0.6000.16543", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"posix.exe", version:"6.0.6000.20660", min_version:"6.0.6000.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:1, file:"posix.exe", version:"9.0.3790.2983", min_version:"9.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"posix.exe", version:"9.0.3790.4125", min_version:"9.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
