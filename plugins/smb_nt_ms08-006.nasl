#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(31040);
 script_version("$Revision: 1.26 $");
 script_cvs_date("$Date: 2016/12/09 20:54:59 $");

 script_cve_id("CVE-2008-0075");
 script_bugtraq_id(27676);
 script_osvdb_id(41445);
 script_xref(name:"MSFT", value:"MS08-006");

 script_name(english:"MS08-006: Vulnerability in Internet Information Services Could Allow Remote Code Execution (942830)");
 script_summary(english:"Determines if hotfix 942830 has been installed");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to use the remote web server to exploit arbitrary code
on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows and IIS that is
vulnerable to a flaw that could allow an attacker who has the privileges
to upload arbitrary ASP scripts to it to execute arbitrary code.

Specifically, the remote version of IIS is vulnerable to a flaw when
parsing specially crafted ASP files.  By uploading a malicious ASP file
on the remote host, an attacker may be able to take the complete control
of the remote system.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS08-006");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows XP and 2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_cwe_id(94);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/02/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/02/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/12");

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

bulletin = 'MS08-006';
kb = '942830';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'2', win2003:'1,2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_iis_installed() <= 0) audit(AUDIT_NOT_INST, "IIS");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"asp.dll", version:"6.0.3790.4195", dir:"\system32\inetsrv", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:1, file:"asp.dll", version:"6.0.3790.3050", dir:"\system32\inetsrv", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, file:"asp.dll", version:"5.1.2600.3291", dir:"\system32\inetsrv", bulletin:bulletin, kb:kb)
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
