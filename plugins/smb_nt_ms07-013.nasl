#
# Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(24337);
 script_version("$Revision: 1.33 $");
 script_cvs_date("$Date: 2015/05/07 12:06:03 $");

 script_cve_id("CVE-2006-1311");
 script_bugtraq_id(21876);
 script_osvdb_id(31886);
 script_xref(name:"MSFT", value:"MS07-013");
 script_xref(name:"CERT", value:"368132");

 script_name(english:"MS07-013: Vulnerability in Microsoft RichEdit Could Allow Remote Code Execution (918118)");
 script_summary(english:"Determines the presence of update 918118");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the RichEdit
component provided with Microsoft Windows and Microsoft Office");
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of Microsoft Windows and/or
Microsoft Office that has a vulnerability in the RichEdit component that
could be abused by an attacker to execute arbitrary code on the remote
host.

To exploit this vulnerability, an attacker would need to spend a
specially crafted RTF file to a user on the remote host and lure him
into opening it.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS07-013");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/13");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/02/13");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/13");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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

bulletin = 'MS07-013';
kbs = make_list("918118", "920813", "920816");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2', win2003:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);


e = 0;

#
# Windows
#
kb = "918118";
if (
  hotfix_is_vulnerable(os:"5.2", sp:1, file:"Riched20.dll", version:"5.31.23.1226", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:0, file:"Riched20.dll", version:"5.31.23.1224", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, file:"Riched20.dll", version:"5.30.23.1228", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0", file:"Riched20.dll", version:"5.30.23.1227", dir:"\system32", bulletin:bulletin, kb:kb)
) e++;

office_versions = hotfix_check_office_version();
if (!isnull(office_versions))
{
  rootfiles = hotfix_get_officecommonfilesdir();
  if (office_versions["11.0"]) # Office 2003
  {
    if (typeof(rootfiles) == 'array') rootfile = rootfiles["11.0"];
    else rootfile = rootfiles;
    if ( hotfix_check_fversion(path:rootfile, file:"\Microsoft Shared\Office11\Riched20.dll", version:"5.50.99.2014", bulletin:bulletin, kb:"920813") == HCF_OLDER ) e ++;
  }
  if (office_versions["10.0"] )  # Office XP
  {
    if (typeof(rootfiles)=='array') rootfile = rootfiles["10.0"];
    else rootfile = rootfiles;
    if ( hotfix_check_fversion(path:rootfile, file:"\Microsoft Shared\Office10\Riched20.dll", version:"5.40.11.2220", bulletin:bulletin, kb:"920816") == HCF_OLDER ) e ++;
  }
}

if (e)
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
