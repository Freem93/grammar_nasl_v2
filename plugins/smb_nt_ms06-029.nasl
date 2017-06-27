#
# Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(21695);
 script_version("$Revision: 1.28 $");
 script_cvs_date("$Date: 2016/06/30 19:55:38 $");

 script_cve_id("CVE-2006-1193");
 script_bugtraq_id(18381);
 script_osvdb_id(26441);
 script_xref(name:"CERT", value:"138188");
 script_xref(name:"MSFT", value:"MS06-029");

 script_name(english:"MS06-029: Vulnerability in Microsoft Exchange Server Running Outlook Web Access Could Allow Script Injection (912442)");
 script_summary(english:"Checks for ms06-029 via the registry");

 script_set_attribute(attribute:"synopsis", value:
"The remote Web Server contains a script that is vulnerable to script injection
attacks.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the Outlook Web Access that contains
cross-site scripting flaws.

This vulnerability could allow an attacker to convince a user
to run a malicious script. If this malicious script is run, it would execute
in the security context of the user.
Attempts to exploit this vulnerability require user interaction.

This vulnerability could allow an attacker access to any data on the
Outlook Web Access server that was accessible to the individual user.

It may also be possible to exploit the vulnerability to manipulate Web browser caches
and intermediate proxy server caches, and put spoofed content in those caches.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms06-029");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for OWA for Exchange 2000/2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/13");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/06/13");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/13");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}

include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_func.inc");


include("misc_func.inc");
get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS06-029';
kb = '912442';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_NOTE);


# now check for the patch
if ( hotfix_check_nt_server() <= 0 )
	exit(0);

version = get_kb_item ("SMB/Exchange/Version");

if (!get_kb_item ("SMB/Exchange/OWA"))
  exit (0);


if (version == 60)
{
 if (is_accessible_share())
 {
  rootfile = get_kb_item("SMB/Exchange/Path");
  if ( ! rootfile ) exit(1);

  rootfile = rootfile + "\bin";
  if ( hotfix_check_fversion(path:rootfile, file:"Mdbmsg.dll", version:"6.5.7233.69", bulletin:bulletin, kb:kb) == HCF_OLDER )
  {
 {
 set_kb_item(name:"SMB/Missing/MS06-029", value:TRUE);
 hotfix_security_note();
 }
   set_kb_item(name: 'www/0/XSS', value: TRUE);
  }
  else if ( hotfix_check_fversion(path:rootfile, file:"Mdbmsg.dll", version:"6.5.7650.28", min_version:"6.5.0.0", bulletin:bulletin, kb:kb) == HCF_OLDER )
  {
 {
 set_kb_item(name:"SMB/Missing/MS06-029", value:TRUE);
 hotfix_security_note();
 }
   set_kb_item(name: 'www/0/XSS', value: TRUE);
  }

  hotfix_check_fversion_end();
 }
 else if ( hotfix_missing(name:"912442") > 0 )
 {
	 {
 set_kb_item(name:"SMB/Missing/MS06-029", value:TRUE);
 hotfix_security_note();
 }
   set_kb_item(name: 'www/0/XSS', value: TRUE);
 }
}
else if (version == 65)
{
 if (is_accessible_share())
 {
  rootfile = get_kb_item("SMB/Exchange/Path");
  if ( ! rootfile ) exit(1);

  rootfile = rootfile + "\bin";
  if ( hotfix_check_fversion(path:rootfile, file:"Mdbmsg.dll", version:"5.5.2658.34", bulletin:bulletin, kb:kb) == HCF_OLDER )
 {
 {
 set_kb_item(name:"SMB/Missing/MS06-029", value:TRUE);
 hotfix_security_note();
 }
  set_kb_item(name: 'www/0/XSS', value: TRUE);
 }

  hotfix_check_fversion_end();
 }
 else if ( hotfix_missing(name:"912442") > 0 )
 {
	 {
 set_kb_item(name:"SMB/Missing/MS06-029", value:TRUE);
 hotfix_security_note();
 }
  set_kb_item(name: 'www/0/XSS', value: TRUE);
 }
}
