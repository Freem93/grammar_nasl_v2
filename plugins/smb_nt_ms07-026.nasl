#
# Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(25165);
 script_version("$Revision: 1.27 $");
 script_cvs_date("$Date: 2015/05/07 12:06:03 $");

 script_cve_id("CVE-2007-0220", "CVE-2007-0039", "CVE-2007-0213", "CVE-2007-0221");
 script_bugtraq_id(23806, 23808, 23809, 23810);
 script_osvdb_id(34389, 34390, 34391, 34392);
 script_xref(name:"IAVA", value:"2007-A-0031");
 script_xref(name:"MSFT", value:"MS07-026");
 script_xref(name:"CERT", value:"124113");
 script_xref(name:"CERT", value:"343145");

 script_name(english:"MS07-026: Vulnerability in Microsoft Exchange Could Allow Remote Code Execution (931832)");
 script_summary(english:"Determines the version of Exchange");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the email server.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of exchange that is vulnerable
to a bug in the iCal attachment and MIME decoding routines, as well
as in the IMAP literal processing and in OWA.

These vulnerabilities could allow an attacker execute arbitrary code on the
remote host.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS07-026");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Exchange 2000 and 2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/08");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/05/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/08");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
 script_set_attribute(attribute:"stig_severity", value:"I");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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

bulletin = 'MS07-026';
kbs = make_list("931832", "935490");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


version = get_kb_item ("SMB/Exchange/Version");
if ( !version ) exit (0);

port = get_kb_item ("SMB/transport");


# 2000
if (version == 60)
{
 sp = get_kb_item ("SMB/Exchange/SP");
 rootfile = get_kb_item("SMB/Exchange/Path");
 if ( ! rootfile || ( sp && sp > 4) ) exit(0);
 rootfile = rootfile + "\bin";
 if ( hotfix_check_fversion(path:rootfile, file:"Cdoex.dll", version:"6.0.6619.12", bulletin:bulletin, kb:'931832') == HCF_OLDER ) {
 set_kb_item(name:"SMB/Missing/MS07-026", value:TRUE);
 hotfix_security_hole();
 }

 hotfix_check_fversion_end();
}
# 2003
else if (version == 65)
{
 sp = get_kb_item ("SMB/Exchange/SP");
 rootfile = get_kb_item("SMB/Exchange/Path");
 if ( ! rootfile || ( sp && sp > 2) ) exit(0);
 rootfile = rootfile + "\bin";
 if (!sp || sp < 1) {
 set_kb_item(name:"SMB/Missing/MS07-026", value:TRUE);
 hotfix_security_hole();
 }
 else if (sp == 2)
 {
  if ( hotfix_check_fversion(path:rootfile, file:"Cdoex.dll", version:"6.5.7652.24", bulletin:bulletin, kb:'931832') == HCF_OLDER ) {
 set_kb_item(name:"SMB/Missing/MS07-026", value:TRUE);
 hotfix_security_hole();
 }
 }
 else if (sp == 1)
 {
  if ( hotfix_check_fversion(path:rootfile, file:"Cdoex.dll", version:"6.5.7235.2", bulletin:bulletin, kb:'931832') == HCF_OLDER ) {
 set_kb_item(name:"SMB/Missing/MS07-026", value:TRUE);
 hotfix_security_hole();
 }
 }

 hotfix_check_fversion_end();
}
else if (version == 80)
{
 sp = get_kb_item ("SMB/Exchange/SP");
 rootfile = get_kb_item("SMB/Exchange/Path");
 if ( ! rootfile || ( sp && sp > 0 ) ) exit(0);
 rootfile = rootfile + "\bin";
 if ( hotfix_check_fversion(path:rootfile, file:"Exmime.dll", version:"8.0.709.0", bulletin:bulletin, kb:'935490') == HCF_OLDER ) {
 set_kb_item(name:"SMB/Missing/MS07-026", value:TRUE);
 hotfix_security_hole();
 }

 hotfix_check_fversion_end();
}
