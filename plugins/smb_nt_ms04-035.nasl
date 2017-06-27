#
# (C) Tenable Network Security, Inc.
#
#
# This test is a registry check which complements what mssmtp_code_execution.nasl
# discovers over the network
#

include("compat.inc");

if (description)
{
 script_id(17976);
 script_version("$Revision: 1.30 $");
 script_cvs_date("$Date: 2016/07/20 14:03:38 $");

 script_cve_id("CVE-2004-0840");
 script_bugtraq_id(11374);
 script_osvdb_id(10696);
 script_xref(name:"MSFT", value:"MS04-035");

 script_name(english:"MS04-035: Vulnerability in SMTP Could Allow Remote Code Execution (885881)");
 script_summary(english:"Checks for MS Hotfix K885881");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote host contains a flaw in its SMTP service that could allow
remote code execution.

Vulnerable services are SMTP service (Windows 2003), Exchange 2003
(Windows 2000) and Exchange 2000.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms04-035");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Exchange 2000 and 2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/10/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/06");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


include("misc_func.inc");
get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS04-035';
kb       = '885881';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

if ( hotfix_check_nt_server() <= 0 ) exit(0);


# Superseeded by MS05-021
if ( hotfix_missing(name:"894549") > 0 ) exit(0);

win = get_kb_item ("SMB/WindowsVersion");
version = get_kb_item ("SMB/Exchange/Version");
sp = get_kb_item ("SMB/Exchange/SP");

if ("5.2" >< win)
{
 sp  = get_kb_item("SMB/CSDVersion");
 if ( sp ) exit (0);

 value = get_kb_item("SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Services/SMTPSVC/DisplayName");
 if (value)
 {
  if (is_accessible_share())
  {
   if ( hotfix_is_vulnerable(os:"5.2", sp:0, file:"Reapi.dll", version:"6.0.3790.211", dir:"\system32\inetsrv") )
 {
 set_kb_item(name:"SMB/Missing/MS04-035", value:TRUE);
 hotfix_add_report(bulletin:bulletin, kb:kb);
 hotfix_security_hole();
 }
  }
  else if ( hotfix_missing(name:"885881") > 0 )
 {
 set_kb_item(name:"SMB/Missing/MS04-035", value:TRUE);
 hotfix_add_report(bulletin:bulletin, kb:kb);
 hotfix_security_hole();
 }
 }
 exit (0);
}

if (("5.0" >< win) && (version == 65))
{
 if (sp && (sp >= 1)) exit (0);

 if (is_accessible_share())
 {
  path = get_kb_item ("SMB/Exchange/Path") + "\bin";
  if ( hotfix_is_vulnerable(os:"5.0", file:"Reapi.dll", version:"6.5.6980.98", dir:path) )
 {
 set_kb_item(name:"SMB/Missing/MS04-035", value:TRUE);
 hotfix_add_report(bulletin:bulletin, kb:kb);
 hotfix_security_hole();
 }
  hotfix_check_fversion_end();
 }
 else if ( hotfix_missing(name:"885882") > 0 )
 {
 set_kb_item(name:"SMB/Missing/MS04-035", value:TRUE);
 hotfix_add_report(bulletin:bulletin, kb:kb);
 hotfix_security_hole();
 }

 exit (0);
}

if (version == 60)
{
 if (sp && (sp >= 4)) exit (0);

 if (is_accessible_share())
 {
  path = get_kb_item ("SMB/Exchange/Path") + "\bin";
  if ( hotfix_is_vulnerable(os:"5.0", file:"Reapi.dll", version:"6.0.6617.25", dir:path, bulletin:bulletin, kb:kb) )
 {
 set_kb_item(name:"SMB/Missing/MS04-035", value:TRUE);
 hotfix_security_hole();
 }
  hotfix_check_fversion_end();
 }
 else if ( hotfix_missing(name:"890066") > 0 )
 {
 set_kb_item(name:"SMB/Missing/MS04-035", value:TRUE);
 hotfix_add_report(bulletin:bulletin, kb:kb);
 hotfix_security_hole();
 }

 exit (0);
}
