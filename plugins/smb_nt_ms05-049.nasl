#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(20002);
 script_version("$Revision: 1.31 $");
 script_cvs_date("$Date: 2015/05/07 12:06:03 $");

 script_cve_id("CVE-2005-2122", "CVE-2005-2118", "CVE-2005-2117");
 script_bugtraq_id(15070, 15069, 15064);
 script_osvdb_id(19898, 19899, 19900);
 script_xref(name:"MSFT", value:"MS05-049");
 script_xref(name:"CERT", value:"922708");

 script_name(english:"MS05-049: Vulnerabilities in Windows Shell Could Allow Remote Code Execution (900725)");
 script_summary(english:"Determines the presence of update 900725");

 script_set_attribute(attribute:"synopsis", value:
"Vulnerabilities in the Windows Shell could allow an attacker to execute
arbitrary code on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a version of the Windows Shell
that has several vulnerabilities.  An attacker may exploit these
vulnerabilities by :

  - Sending a malformed .lnk file a to user on the remote
    host to trigger an overflow.

  - Sending a malformed HTML document to a user on the
    remote host and have him view it in the Windows
    Explorer preview pane.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms05-049");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/11");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/10/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/11");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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

bulletin = 'MS05-049';
kb = '900725';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'1,2', win2003:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"5.2", sp:0, file:"shell32.dll", version:"6.0.3790.413", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:1, file:"shell32.dll", version:"6.0.3790.2534", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:1, file:"shell32.dll", version:"6.0.2800.1751", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, file:"shell32.dll", version:"6.0.2900.2763", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0",       file:"shell32.dll", version:"5.0.3900.7071", dir:"\system32", bulletin:bulletin, kb:kb)
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
