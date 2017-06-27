#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(31039);
 script_version("$Revision: 1.25 $");
 script_cvs_date("$Date: 2015/04/23 21:11:57 $");

 script_cve_id("CVE-2008-0074");
 script_bugtraq_id(27101);
 script_osvdb_id(41456);
 script_xref(name:"MSFT", value:"MS08-005");

 script_name(english:"MS08-005: Vulnerability in Internet Information Services Could Allow Elevation of Privilege (942831)");
 script_summary(english:"Checks the remote file version for 942831");

 script_set_attribute(attribute:"synopsis", value:"A local user can elevate his privileges on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of Microsoft Internet Information
Services (IIS) that is vulnerable to a security flaw that could allow a
local user to elevate his privileges to SYSTEM due to a bug in the way
IIS handles file change notifications in the FTPRoot, NNTPFile\Root and
WWWRoot folders.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS08-005");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, Windows XP,
Windows 2003 Server and Windows Vista.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(264);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/02/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/02/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/12");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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

bulletin = 'MS08-005';
kb = '942831';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2', win2003:'1,2', vista:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_iis_installed() <= 0) audit(AUDIT_NOT_INST, "IIS");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"infocomm.dll", version:"7.0.6000.20698", min_version:"7.0.6000.20000", dir:"\system32\inetsrv", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"infocomm.dll", version:"7.0.6000.16576", dir:"\system32\inetsrv", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.2", sp:2, file:"infocomm.dll", version:"6.0.3790.4215", dir:"\system32\inetsrv", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:1, file:"infocomm.dll", version:"6.0.3790.3068", dir:"\system32\inetsrv", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.1", sp:2, file:"infocomm.dll", version:"6.0.2600.3290", dir:"\system32\inetsrv", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.0", file:"infocomm.dll", version:"5.0.2195.7147", dir:"\system32\inetsrv", bulletin:bulletin, kb:kb)
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
