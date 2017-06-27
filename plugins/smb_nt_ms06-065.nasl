#
# Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(22538);
 script_version("$Revision: 1.24 $");
 script_cvs_date("$Date: 2015/04/23 21:04:51 $");

 script_cve_id("CVE-2006-4692");
 script_bugtraq_id(20318);
 script_osvdb_id(29424);
 script_xref(name:"CERT", value:"703936");
 script_xref(name:"MSFT", value:"MS06-065");

 script_name(english:"MS06-065: Vulnerability in Windows Object Packager Could Allow Remote Execution (924496)");
 script_summary(english:"Checks the remote registry for 9224496");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute code on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote host runs a version of Windows that has a flaw in its Object
Packager.

The flaw could allow an attacker to execute code on the remote host.

To exploit this vulnerability, an attacker needs to entice a user to
visit a malicious website.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms06-065");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows XP and 2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/10/10");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/10/10");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/10");

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
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS06-065';
kb = '924496';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'1,2', win2003:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if ( hotfix_is_vulnerable(os:"5.2", sp:0, file:"Shdocvw.dll", version:"6.0.3790.588", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.2", sp:1, file:"Shdocvw.dll", version:"6.0.3790.2783", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.1", sp:1, file:"Shdocvw.dll", version:"6.0.2800.1892", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.1", sp:2, file:"Shdocvw.dll", version:"6.0.2900.2987", dir:"\system32", bulletin:bulletin, kb:kb) )
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
