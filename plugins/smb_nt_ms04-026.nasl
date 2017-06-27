#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14254);
 script_version("$Revision: 1.33 $");
 script_cvs_date("$Date: 2015/04/23 21:04:49 $");

 script_cve_id("CVE-2004-0203");
 script_bugtraq_id(10902);
 script_osvdb_id(8407);
 script_xref(name:"MSFT", value:"MS04-026");

 script_name(english:"MS04-026: Vulnerability in Exchange Server 5.5 Outlook Web Access XSS (842436)");
 script_summary(english:"Checks for ms04-026 via the registry");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server runs a script vulnerable to cross-site scripting
attacks.");
 script_set_attribute(attribute:"description", value:
"The remote host runs Outlook Web Access.

Outlook Web Access is a service for Microsoft Exchange, that provides
web-based email, calendaring and contact management to end users.

The remote version of Outlook Web Access is vulnerable to a cross-site
scripting attack that could allow an attacker to execute arbitrary java
script in the security context of a victim using this service.

To exploit this flaw, an attacker would need to send a specially crafted
message to a victim using Outlook Web Access.  When the victim reads the
message, the bug in Outlook Web Access triggers and cause the execution
of the script sent by the attacker.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms04-026");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for OWA for Exchange 5.5.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/10");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/08/10");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/10");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
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

bulletin = 'MS04-026';
kb = '842436';

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
  # ms04-26 = 5.5.2658.1080, ms05-029 = 5.5.2658.34 ???
  if ( hotfix_check_fversion(path:rootfile, file:"cdo.dll", version:"5.5.2658.34", bulletin:bulletin, kb:kb) == HCF_OLDER )
  {
 {
 set_kb_item(name:"SMB/Missing/MS04-026", value:TRUE);
 hotfix_security_warning();
 }
   set_kb_item(name: 'www/0/XSS', value: TRUE);
  }

  hotfix_check_fversion_end();
 }
 else if ( hotfix_missing(name:"842436") > 0 )
 {
	 {
 set_kb_item(name:"SMB/Missing/MS04-026", value:TRUE);
 hotfix_add_report(bulletin:bulletin, kb:kb);
 hotfix_security_warning();
 }
  set_kb_item(name: 'www/0/XSS', value: TRUE);
 }
}
