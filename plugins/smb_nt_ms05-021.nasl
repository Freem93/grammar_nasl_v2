#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(18024);
 script_version("$Revision: 1.37 $");
 script_cvs_date("$Date: 2015/05/07 12:06:03 $");
 script_cve_id("CVE-2005-0560");
 script_bugtraq_id(13118);
 script_osvdb_id(15467);
 script_xref(name:"MSFT", value:"MS05-021");
 script_xref(name:"CERT", value:"275193");
 script_xref(name:"EDB-ID", value:"947");

 script_name(english:"MS05-021: Vulnerability in SMTP Could Allow Remote Code Execution (894549)");
 script_summary(english:"Checks for MS Hotfix 894549");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the SMTP server.");
 script_set_attribute(attribute:"description", value:
"The remote host contains a flaw in its SMTP service that could allow remote
code execution.

Vulnerable services are Exchange 2003 (Windows 2000) and Exchange 2000.

A public code is available to exploit this vulnerability.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms05-021");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Exchange 2000 and 2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/04/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/12");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}

include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");


include("misc_func.inc");
get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS05-021';
kb = '894549';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

if ( hotfix_check_nt_server() <= 0 ) exit(0);

version = get_kb_item ("SMB/Exchange/Version");
sp = get_kb_item ("SMB/Exchange/SP");


if ( ! version ) exit(0);


if ( version == 65 )
{
 if (sp && (sp >= 2)) exit (0);

 if (is_accessible_share())
 {
  if (sp)
  {
   if ( hotfix_check_fversion(file:"Xlsasink.dll", version:"6.5.7232.89", path:get_kb_item("SMB/Exchange/Path") + "\bin", bulletin:bulletin, kb:kb) == HCF_OLDER ) {
 set_kb_item(name:"SMB/Missing/MS05-021", value:TRUE);
 hotfix_security_hole();
 }
  }
  else
  {
   if ( hotfix_check_fversion(file:"Xlsasink.dll", version:"6.5.6981.3", path:get_kb_item("SMB/Exchange/Path") + "\bin", bulletin:bulletin, kb:kb) == HCF_OLDER ) {
 set_kb_item(name:"SMB/Missing/MS05-021", value:TRUE);
 hotfix_security_hole();
 }
  }
  hotfix_check_fversion_end();
 }
 else
 {
  if ( hotfix_missing(name:"894549") > 0 )
 {
 set_kb_item(name:"SMB/Missing/MS05-021", value:TRUE);
 hotfix_add_report(bulletin:bulletin, kb:kb);
 hotfix_security_hole();
 }
 }
 exit (0);
}

if (version == 60)
{
 if (sp && (sp >= 4)) exit (0);

 if (is_accessible_share())
 {
  if ( hotfix_check_fversion(file:"Xlsasink.dll", version:"6.0.6617.52", path:get_kb_item("SMB/Exchange/Path") + "\bin", bulletin:bulletin, kb:kb) == HCF_OLDER ) {
 set_kb_item(name:"SMB/Missing/MS05-021", value:TRUE);
 hotfix_security_hole();
 }
  hotfix_check_fversion_end();
 }
 else
 {
  if ( hotfix_missing(name:"894549") > 0 )
 {
 set_kb_item(name:"SMB/Missing/MS05-021", value:TRUE);
 hotfix_add_report(bulletin:bulletin, kb:kb);
 hotfix_security_hole();
 }
 }
 exit (0);
}
