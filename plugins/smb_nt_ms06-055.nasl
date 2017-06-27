#
# Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(22449);
 script_version("$Revision: 1.39 $");
 script_cvs_date("$Date: 2016/12/09 20:54:59 $");

 script_cve_id("CVE-2006-4868");
 script_bugtraq_id(20096);
 script_osvdb_id(28946);
 script_xref(name:"CERT", value:"416092");
 script_xref(name:"MSFT", value:"MS06-055");

 script_name(english:"MS06-055: Vulnerability in Vector Markup Language Could Allow Remote Code Execution (925486)");
 script_summary(english:"Determines the presence of update 925486");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the email client or
the web browser.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Internet Explorer or Outlook Express
that is vulnerable to a bug in the Vector Markup Language (VML) handling routine
that could allow an attacker execute arbitrary code on the remote host by sending
a specially crafted email or by luring a user on the remote host into visiting
a rogue website.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms06-055");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'MS06-055 Microsoft Internet Explorer VML Fill Method Code Execution');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/18");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/09/26");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/26");

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
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS06-055';
kb = '925486';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'1,2', win2003:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

dir = hotfix_get_commonfilesdir();
if (!dir) exit(1, "Failed to get the common files directory.");

share = hotfix_path2share(path:dir);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if ( hotfix_is_vulnerable(os:"5.2", sp:0, file:"Vgx.dll", version:"6.0.3790.593", dir:"\Microsoft Shared\VGX", path:dir, bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.2", sp:1, file:"Vgx.dll", version:"6.0.3790.2794", dir:"\Microsoft Shared\VGX", path:dir, bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.1", sp:1, file:"Vgx.dll", version:"6.0.2800.1580", dir:"\Microsoft Shared\VGX", path:dir, bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.1", sp:2, file:"Vgx.dll", version:"6.0.2900.2997", dir:"\Microsoft Shared\VGX", path:dir, bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.0", file:"Vgx.dll", version:"6.0.2800.1580", min_version:"6.0.0.0", dir:"\Microsoft Shared\VGX", path:dir, bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.0", file:"Vgx.dll", version:"5.0.3845.1800", dir:"\Microsoft Shared\VGX", path:dir, bulletin:bulletin, kb:kb) )
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
