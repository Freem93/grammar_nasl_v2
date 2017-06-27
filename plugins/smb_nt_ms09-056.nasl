#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42112);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/12/09 21:04:53 $");

  script_cve_id("CVE-2009-2510", "CVE-2009-2511");
  script_bugtraq_id(36475, 36577);
  script_osvdb_id(58855, 58856);
  script_xref(name:"IAVA", value:"2009-A-0095");
  script_xref(name:"MSFT", value:"MS09-056");
  script_xref(name:"EDB-ID", value:"33264");

  script_name(english:"MS09-056: Vulnerabilities in Windows CryptoAPI Could Allow Spoofing (974571)");
  script_summary(english:"Checks version of msasn1.dll");

  script_set_attribute(attribute:"synopsis", value:
"Certain identity validation methods may be bypassed allowing
impersonation.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of the Microsoft Windows
CryptoAPI that is affected by multiple vulnerabilities :

  - A spoofing vulnerability exists in the Microsoft Windows
    CryptoAPI component when parsing ASN.1 information from
    X.509 certificates. An attacker who successfully
    exploited this vulnerability could impersonate another
    user or system. (CVE-2009-2510)

  - A spoofing vulnerability exists in the Microsoft Windows
    CryptoAPI component when parsing ASN.1 object
    identifiers from X.509 certificates. An attacker who
    successfully exploited this vulnerability could
    impersonate another user or system. (CVE-2009-2511)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS09-056");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista, 2008 and Windows 7.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(189, 310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
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


include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS09-056';
kb = '974571';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'2', vista:'0,2', win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 7
  hotfix_is_vulnerable(os:"6.1", sp:0,  file:"msasn1.dll", version:"6.1.7600.16415", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0,  file:"msasn1.dll", version:"6.1.7600.20518", min_version:"6.1.7600.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Vista / 2k8
  hotfix_is_vulnerable(os:"6.0", sp:0,  file:"msasn1.dll", version:"6.0.6000.16922", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0,  file:"msasn1.dll", version:"6.0.6000.21122", min_version:"6.0.6000.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1,  file:"msasn1.dll", version:"6.0.6001.18326", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1,  file:"msasn1.dll", version:"6.0.6001.22515", min_version:"6.0.6001.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2,  file:"msasn1.dll", version:"6.0.6002.18106", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2,  file:"msasn1.dll", version:"6.0.6002.22218", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2003 x86 and x64
  hotfix_is_vulnerable(os:"5.2", file:"msasn1.dll", version:"5.2.3790.4584", min_version:"5.2.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows XP x64
  hotfix_is_vulnerable(os:"5.1", arch:"x64", file:"msasn1.dll", version:"5.2.3790.4584", min_version:"5.2.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"msasn1.dll", version:"5.1.2600.3624", min_version:"5.1.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"msasn1.dll", version:"5.1.2600.5875", min_version:"5.1.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0", file:"msasn1.dll", version:"5.0.2195.7334", min_version:"5.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb)
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
