#
# Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(20001);
 script_version("$Revision: 1.30 $");
 script_cvs_date("$Date: 2015/05/07 12:06:03 $");

 script_cve_id("CVE-2005-1987");
 script_bugtraq_id(15067);
 script_osvdb_id(19905);
 script_xref(name:"MSFT", value:"MS05-048");
 script_xref(name:"CERT", value:"883460");

 script_name(english:"MS05-048: Vulnerability in the Microsoft Collaboration Data Objects Could Allow Remote Code Execution (907245)");
 script_summary(english:"Determines the presence of update 907245");

 script_set_attribute(attribute:"synopsis", value:
"A flaw in the Microsoft Collaboration Data Object could allow an
attacker to execute arbitrary code on the remote host.");
 script_set_attribute(attribute:"description", value:
"An unchecked buffer condition could allow an attacker to execute
arbitrary code on the remote host.

To execute this flaw, an attacker would need to send a malformed message
via SMTP to the remote host, either by using the SMTP server (if
Exchange is installed) or by sending an email to a user on the remote
host.

When the email is processed by CDO, an unchecked buffer may allow cause
code execution.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms05-048");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

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

bulletin = 'MS05-048';
kbs = make_list("901017", "906780");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'1,2', win2003:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);


vuln = 0;

kb = '901017';
if (
  hotfix_is_vulnerable(os:"5.2", sp:0, file:"cdosys.dll", version:"6.5.6749.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:1, file:"cdosys.dll", version:"6.5.6756.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:1, file:"cdosys.dll", version:"6.1.1002.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, file:"cdosys.dll", version:"6.2.4.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0", file:"cdosys.dll", version:"6.1.3940.42", dir:"\system32", bulletin:bulletin, kb:kb)
) vuln++;


kb = '906780';
version = get_kb_item("SMB/Exchange/Version");
if (version == 60)
{
  sp = get_kb_item("SMB/Exchange/SP");
  if (sp && sp >= 4) exit(0, "The host has Exchange 2000 SP "+sp+" and is not affected.");

  path = get_kb_item("SMB/Exchange/Path");
  if (!path) exit(1, "Failed to get the installation directory of Exchange 2000.");

  share = hotfix_path2share(path:path);
  if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

  path = path + "\bin";
  if (hotfix_check_fversion(path:path, file:"cdoex.dll", version:"6.0.6617.86", bulletin:bulletin, kb:kb) == HCF_OLDER) vuln++;
}


if (vuln)
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
