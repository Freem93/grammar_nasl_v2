#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(33443);
 script_version("$Revision: 1.26 $");
 script_cvs_date("$Date: 2016/06/30 19:55:38 $");

 script_cve_id("CVE-2008-2247", "CVE-2008-2248");
 script_bugtraq_id(30078, 30130);
 script_osvdb_id(46779, 46780);
 script_xref(name:"MSFT", value:"MS08-039");
 script_xref(name:"IAVT", value:"2008-T-0033");

 script_name(english:"MS08-039: Vulnerabilities in Outlook Web Access for Exchange Server Could Allow Elevation of Privilege (953747)");
 script_summary(english:"Determines the version of Exchange");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to cross-site scripting issues.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Outlook Web Access (OWA) for
Exchange Server that is vulnerable to multiple cross-site scripting
issues in the HTML parser and Data validation code.

These vulnerabilities may allow an attacker to elevate his privileges
by convincing a user to open a malformed email.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms08-039");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for OWA 2003 and 2007.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/07/08");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/07/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/08");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
 script_set_attribute(attribute:"stig_severity", value:"II");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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

bulletin = 'MS08-039';
kbs = make_list("950159");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);


version = get_kb_item ("SMB/Exchange/Version");
if ( !version ) exit (0);

path2003 = get_kb_item("SMB/Exchange/Path") + "\exchweb\bin\auth";
path2007 = hotfix_get_commonfilesdir() + "\Microsoft Shared\CDO";



if ( ( hotfix_check_fversion(path:path2003, file:"Owaauth.dll", version:"6.5.7653.38", bulletin:bulletin, kb:'950159') == HCF_OLDER ) ||
     ( hotfix_check_fversion(path:path2007, file:"Cdoex.dll", version:"8.1.291.1", min_version:"8.1.0.0", bulletin:bulletin, kb:'949870') == HCF_OLDER ) ||
     ( hotfix_check_fversion(path:path2007, file:"Cdoex.dll", version:"8.0.813.0", min_version:"8.0.0.0", bulletin:bulletin, kb:'953469') == HCF_OLDER ) )
{
 {
 set_kb_item(name:"SMB/Missing/MS08-039", value:TRUE);
 hotfix_security_warning();
 }
 set_kb_item(name: 'www/0/XSS', value: TRUE);
}

hotfix_check_fversion_end();
