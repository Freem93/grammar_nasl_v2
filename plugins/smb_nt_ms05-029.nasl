#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(18488);
 script_version("$Revision: 1.31 $");
 script_cvs_date("$Date: 2015/05/07 12:06:03 $");

 script_cve_id("CVE-2005-0563");
 script_bugtraq_id(13952);
 script_osvdb_id(17307);
 script_xref(name:"MSFT", value:"MS05-029");
 script_xref(name:"CERT", value:"300373");

 script_name(english:"MS05-029: Vulnerability in Exchange Server 5.5 Outlook Web Access XSS (895179)");
 script_summary(english:"Checks for ms05-029 via the registry");

 script_set_attribute(attribute:"synopsis", value:
"The remote Web Server contains a script that is vulnerable to a
cross-site scripting attack.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the Outlook Web Access that is
affected by a cross-site scripting flaw.

This vulnerability could allow an attacker to convince a user to run a
malicious script.  If this malicious script is run, it would execute in
the security context of the user.

Attempts to exploit this vulnerability require user interaction.

This vulnerability could allow an attacker access to any data on the
Outlook Web Access server that was accessible to the individual user.

It may also be possible to exploit the vulnerability to manipulate Web
browser caches and intermediate proxy server caches, and put spoofed
content in those caches.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms05-029");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for OWA for Exchange 5.5.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/14");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/06/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/06/14");

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

include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_func.inc");


include("misc_func.inc");
get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS05-029';
kb = '895179';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

# now check for the patch
if ( hotfix_check_nt_server() <= 0 )
	exit(0);

version = get_kb_item ("SMB/Exchange/Version");


if (version == 55)
{
 if (!get_kb_item ("SMB/Exchange/OWA"))
   exit (0);

 if (is_accessible_share())
 {
  rootfile = get_kb_item("SMB/Exchange/Path");
  if ( ! rootfile ) exit(1);

  rootfile = rootfile + "\bin";
  if ( hotfix_check_fversion(path:rootfile, file:"cdo.dll", version:"5.5.2658.34", bulletin:bulletin, kb:kb) == HCF_OLDER )
  {
 {
 set_kb_item(name:"SMB/Missing/MS05-029", value:TRUE);
 hotfix_security_warning();
 }
   set_kb_item(name: 'www/0/XSS', value: TRUE);
  }

  hotfix_check_fversion_end();
 }
 else if ( hotfix_missing(name:"895179") > 0 )
 {
	 {
 set_kb_item(name:"SMB/Missing/MS05-029", value:TRUE);
 hotfix_add_report(bulletin:bulletin, kb:kb);
 hotfix_security_warning();
 }
  set_kb_item(name: 'www/0/XSS', value: TRUE);
 }
}
