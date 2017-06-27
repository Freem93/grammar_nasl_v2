#
# Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(23646);
 script_version("$Revision: 1.29 $");
 script_cvs_date("$Date: 2016/12/09 20:54:59 $");

 script_cve_id("CVE-2006-4691");
 script_bugtraq_id(20985);
 script_osvdb_id(30263);
 script_xref(name:"MSFT", value:"MS06-070");

 script_name(english:"MS06-070: Vulnerability in Workstation Service Could Allow Remote Code Execution (924270)");
 script_summary(english:"Determines the presence of update 924270");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host due to a flaw in the
'workstation' service.");
 script_set_attribute(attribute:"description", value:
"The remote host is vulnerable to a buffer overrun in the 'workstation' service
that could allow an attacker to execute arbitrary code on the remote host
with the 'System' privileges.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms06-070");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows 2000 and XP.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'MS06-070 Microsoft Workstation Service NetpManageIPCConnect Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/14");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/11/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/11/14");

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

bulletin = 'MS06-070';
kb = '924270';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if ( hotfix_is_vulnerable(os:"5.1", sp:2, file:"Netapi32.dll", version:"5.1.2600.2976", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.0", file:"Netapi32.dll", version:"5.0.2195.7108", dir:"\system32", bulletin:bulletin, kb:kb) )
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
