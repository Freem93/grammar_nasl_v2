#
# Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(21211);
 script_version("$Revision: 1.29 $");
 script_cvs_date("$Date: 2016/12/09 20:54:59 $");

 script_cve_id("CVE-2006-0003");
 script_bugtraq_id(17462);
 script_osvdb_id(24517);
 script_xref(name:"MSFT", value:"MS06-014");

 script_name(english:"MS06-014: Vulnerability in MDAC Could Allow Code Execution (911562)");
 script_summary(english:"Checks the version of MDAC");

 script_set_attribute(attribute:"synopsis", value:
"A local administrator could elevate his privileges on the remote host, through a
flaw in the MDAC server.");
 script_set_attribute(attribute:"description", value:
"The remote Microsoft Data Access Component (MDAC) server is vulnerable to a
flaw that could allow a local administrator to elevate his privileges to the
'system' level, thus gaining the complete control over the remote system.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms06-014");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'MS06-014 Microsoft Internet Explorer COM CreateObject Code Execution');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/04/11");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/04/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/04/11");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS06-014';
kb = '911562';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'1,2', win2003:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

path = hotfix_get_commonfilesdir() + '\\system\\msadc\\';

if (!path) exit(1, "Failed to get the common files directory.");

share = hotfix_path2share(path:path);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if ( hotfix_is_vulnerable(os:"5.2", sp:0, file:"msadco.dll", version:"2.80.1062.0", path:path, bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.2", sp:1, file:"msadco.dll", version:"2.82.2644.0", path:path, bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.1", sp:1, file:"msadco.dll", version:"2.71.9053.0", path:path, bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.1", sp:2, file:"msadco.dll", version:"2.81.1124.0", path:path, bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.0",       file:"msadco.dll", version:"2.53.6306.0", path:path, bulletin:bulletin, kb:kb) )
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
