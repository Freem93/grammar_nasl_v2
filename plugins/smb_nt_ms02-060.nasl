#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11286);
 script_version("$Revision: 1.34 $");
 script_cvs_date("$Date: 2017/05/26 15:15:35 $");

 script_cve_id("CVE-2002-0974");
 script_bugtraq_id(5478);
 script_osvdb_id(3001);
 script_xref(name:"MSFT", value:"MS02-060");
 script_xref(name:"MSKB", value:"328940");

 script_name(english:"MS02-060: Flaw in WinXP Help center could enable file deletion (328940)");
 script_summary(english:"Checks for MS Hotfix Q328940");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary files can be deleted on the remote host through the web
client.");
 script_set_attribute(attribute:"description", value:
"There is a security vulnerability in the remote Windows XP Help and
Support Center which can be exploited by an attacker to delete arbitrary
files on this host.

To do so, an attacker needs to create malicious web pages that must be
visited by the owner of the remote system.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms02-060");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows XP and 2000.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/08/15");
 script_set_attribute(attribute:"patch_publication_date", value:"2002/10/16");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/02/28");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2017 Tenable Network Security, Inc.");
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

bulletin = 'MS02-060';
kb = '328940';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (hotfix_is_vulnerable(os:"5.1", sp:0, file:"Helpctr.exe", version:"5.1.2600.101", dir:"\pchealth\helpctr\binaries", bulletin:bulletin, kb:kb))
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


