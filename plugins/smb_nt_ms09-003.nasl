#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35631);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/12/09 20:55:00 $");

  script_cve_id("CVE-2009-0098", "CVE-2009-0099");
  script_bugtraq_id(33134, 33136);
  script_osvdb_id(51837, 51838);
  script_xref(name:"IAVA", value:"2009-A-0013");
  script_xref(name:"MSFT", value:"MS09-003");

  script_name(english:"MS09-003: Vulnerabilities in Microsoft Exchange Could Allow Remote Code Execution (959239)");
  script_summary(english:"Determines the version of Exchange");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the email
server.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Exchange that is
affected by a memory corruption vulnerability that could lead to
remote code execution when processing a specially crafted TNEF message
as well as a denial of service vulnerability when processing a
specially crafted MAPI command that could cause the Microsoft Exchange
System Attendant service and other services that use the EMSMDB32
provider to stop responding.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS09-003");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Exchange 2000, 2003, and
2007.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/02/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS09-003';
kbs = make_list("959241", "959897");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


version = get_kb_item("SMB/Exchange/Version");
if (!version) exit(0);


# 2000
if (version == 60)
{
  sp = get_kb_item ("SMB/Exchange/SP");
  rootfile = get_kb_item("SMB/Exchange/Path");
  if (!rootfile || (sp && sp > 4)) exit(0);

  rootfile = rootfile + "\bin";
  if (hotfix_check_fversion(path:rootfile, file:"Emsmdb32.dll", version:"6.0.6620.9", bulletin:bulletin, kb:"959897") == HCF_OLDER) {
 set_kb_item(name:"SMB/Missing/MS09-003", value:TRUE);
 hotfix_security_hole();
 }

  hotfix_check_fversion_end();
}
# 2003
else if (version == 65)
{
  sp = get_kb_item ("SMB/Exchange/SP");
  rootfile = hotfix_get_commonfilesdir() + "\Microsoft Shared\CDO";
  if (!rootfile || (sp && sp > 2)) exit(0);

  if (hotfix_check_fversion(path:rootfile, file:"Cdoex.dll", version:"6.5.7654.12", bulletin:bulletin, kb:"959897") == HCF_OLDER) {
 set_kb_item(name:"SMB/Missing/MS09-003", value:TRUE);
 hotfix_security_hole();
 }

  hotfix_check_fversion_end();
}
# 2007
else if (version == 80)
{
  sp = get_kb_item ("SMB/Exchange/SP");
  rootfile = hotfix_get_commonfilesdir() + "\Microsoft Shared\CDO";
  if (!rootfile || (sp && sp > 1)) exit(0);

  if (
    hotfix_check_fversion(path:rootfile, file:"Cdoex.dll", version:"8.1.338.0", min_version:"8.1.0.0", bulletin:bulletin, kb:"959241") == HCF_OLDER ||
    hotfix_check_fversion(path:rootfile, file:"Cdoex.dll", version:"8.0.834.0", bulletin:bulletin, kb:"959241") == HCF_OLDER
  ) {
 set_kb_item(name:"SMB/Missing/MS09-003", value:TRUE);
 hotfix_security_hole();
 }

  hotfix_check_fversion_end();
}
