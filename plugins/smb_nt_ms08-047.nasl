#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(33876);
 script_version("$Revision: 1.23 $");
 script_cvs_date("$Date: 2015/06/23 19:16:51 $");

 script_cve_id("CVE-2008-2246");
 script_bugtraq_id(30634);
 script_osvdb_id(47396);
 script_xref(name:"MSFT", value:"MS08-047");
 script_xref(name:"IAVT", value:"2008-T-0038");

 script_name(english:"MS08-047: Vulnerability in IPsec Policy Processing Could Allow Information Disclosure (953733)");
 script_summary(english:"Determines the presence of update 953733");

 script_set_attribute(attribute:"synopsis", value:
"The remote host IPsec policy processing could lead to information
disclosure.");
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a bug in its IPsec
implementation which might lead to information disclosure.

Specifically, when importing a Windows Server 2003 IPsec policy into a
Windows Server 2008 domain, the system could ignore the IPsec policies
and transmit the traffic in cleartext.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms08-047");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista and Server
2008.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(200);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/08/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/08/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/13");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"stig_severity", value:"I");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}


include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS08-047';
kb = '953733';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"IPsecsvc.dll", version:"6.0.6000.16705", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"IPsecsvc.dll", version:"6.0.6000.20861", min_version:"6.0.6000.20000",  dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"IPsecsvc.dll", version:"6.0.6001.22206", min_version:"6.0.6001.22000",  dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"IPsecsvc.dll", version:"6.0.6001.18094",  dir:"\system32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
