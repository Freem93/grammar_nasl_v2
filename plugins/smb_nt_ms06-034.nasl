#
# Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(22028);
 script_version("$Revision: 1.28 $");
 script_cvs_date("$Date: 2015/04/23 21:04:50 $");

 script_cve_id("CVE-2006-0026");
 script_bugtraq_id(18858);
 script_osvdb_id(27152);
 script_xref(name:"CERT", value:"395588");
 script_xref(name:"MSFT", value:"MS06-034");

 script_name(english:"MS06-034: Vulnerability in Microsoft IIS using ASP Could Allow Remote Code Execution (917537)");
 script_summary(english:"Determines if hotfix 917537 has been installed");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to use the remote web server to exploit arbitrary code on the
remote host.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows and IIS that is
vulnerable to a flaw that could allow an attacker who has the
privileges to upload arbitrary ASP scripts to it to execute arbitrary
code.

Specifically, the remote version of IIS is vulnerable to a flaw when
parsing specially crafted ASP files.  By uploading a malicious ASP file
on the remote host, an attacker may be able to take the complete control
of the remote system.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms06-034");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/11");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/07/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/11");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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

bulletin = 'MS06-034';
kb = '917537';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'1,2', win2003:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if ( hotfix_is_vulnerable(os:"5.2", sp:1, file:"asp.dll", version:"6.0.3790.2684", dir:"\system32\inetsrv", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.2", sp:0, file:"asp.dll", version:"6.0.3790.520", dir:"\system32\inetsrv", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.1", sp:2, file:"asp.dll", version:"5.1.2600.2889", dir:"\system32\inetsrv", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.1", sp:1, file:"asp.dll", version:"5.1.2600.1829", dir:"\system32\inetsrv", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.0", file:"asp.dll", version:"5.0.2195.7084", dir:"\system32\inetsrv", bulletin:bulletin, kb:kb) )
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
