#
# Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(21332);
 script_version("$Revision: 1.31 $");
 script_cvs_date("$Date: 2016/06/30 19:55:38 $");

 script_cve_id("CVE-2006-0027");
 script_bugtraq_id (17908);
 script_osvdb_id(25338);
 script_xref(name:"CERT", value:"303452");
 script_xref(name:"MSFT", value:"MS06-019");

 script_name(english:"MS06-019: Vulnerability in Microsoft Exchange Could Allow Remote Code Execution (916803)");
 script_summary(english:"Determines the version of Exchange");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the email server.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Exchange that is vulnerable to
a bug in the vCal or iCal attachment handling routine that could allow
an attacker execute arbitrary code on the remote host by sending a
specially crafted email.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms06-019");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Exchange 2000 and 2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"exploit_framework_core", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/09");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/05/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/05/09");

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


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


include("misc_func.inc");
get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS06-019';
kb = '916803';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


version = get_kb_item ("SMB/Exchange/Version");
if ( !version ) exit (0);

port = get_kb_item ("SMB/transport");


# 2000
if (version == 60)
{
 sp = get_kb_item ("SMB/Exchange/SP");
 rootfile = get_kb_item("SMB/Exchange/Path");
 if ( ! rootfile || ( sp && sp > 3) ) exit(0);
 rootfile = rootfile + "\bin";
 if ( hotfix_check_fversion(path:rootfile, file:"Cdoex.dll", version:"6.0.6618.4", bulletin:bulletin, kb:kb) == HCF_OLDER ) {
 set_kb_item(name:"SMB/Missing/MS06-019", value:TRUE);
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
 set_kb_item(name:"SMB/Missing/MS06-019", value:TRUE);
 hotfix_security_hole();
 }
 else if (sp == 2)
 {
  if ( hotfix_check_fversion(path:rootfile, file:"Cdoex.dll", version:"6.5.7650.29", bulletin:bulletin, kb:kb) == HCF_OLDER ) {
 set_kb_item(name:"SMB/Missing/MS06-019", value:TRUE);
 hotfix_security_hole();
 }
 }
 else if (sp == 1)
 {
  if ( hotfix_check_fversion(path:rootfile, file:"Cdoex.dll", version:"6.5.7233.69", bulletin:bulletin, kb:kb) == HCF_OLDER ) {
 set_kb_item(name:"SMB/Missing/MS06-019", value:TRUE);
 hotfix_security_hole();
 }
 }

 hotfix_check_fversion_end();
}
