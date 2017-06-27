#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71313);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/04/23 21:44:06 $");

  script_cve_id("CVE-2013-3900");
  script_bugtraq_id(64079);
  script_osvdb_id(100765);
  script_xref(name:"MSFT", value:"MS13-098");
  script_xref(name:"IAVA", value:"2013-A-0227");

  script_name(english:"MS13-098: Vulnerability in Windows Could Allow Remote Code Execution (2893294)");
  script_summary(english:"Checks the file version of imagehlp.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a version of Microsoft Windows that is
affected by a remote code execution vulnerability.  The vulnerability
exists in the method in which the WinVerifyTrust function deals with
Windows Authenticode signature verification for portable executable
files.  An attacker could modify an existing signed executable to add
malicious code without invalidating the signature.  An attacker could
then convince a user to run this signed executable and gain complete
control of the system.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-098");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, 2008 R2, 8, 2012, 8.1 and 2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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

bulletin = 'MS13-098';
kb = '2893294';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # 8.1 / 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"imagehlp.dll", version:"6.3.9600.16438", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # 8.0 / 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"imagehlp.dll", version:"6.2.9200.20856", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"imagehlp.dll", version:"6.2.9200.16745", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # 7 / 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"imagehlp.dll", version:"6.1.7601.22484", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"imagehlp.dll", version:"6.1.7601.18288", min_version:"6.1.7600.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"imagehlp.dll", version:"6.0.6002.23248", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"imagehlp.dll", version:"6.0.6002.18971", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # 2003 / XP-64
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"imagehlp.dll", version:"5.2.3790.5240", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # XP
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"imagehlp.dll", version:"5.1.2600.6479", dir:"\system32", bulletin:bulletin, kb:kb)
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
