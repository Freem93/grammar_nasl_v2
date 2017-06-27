#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81263);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/03/14 19:33:40 $");

  script_cve_id(
    "CVE-2015-0003",
    "CVE-2015-0010",
    "CVE-2015-0057",
    "CVE-2015-0058",
    "CVE-2015-0059",
    "CVE-2015-0060"
  );
  script_bugtraq_id(
    72457,
    72461,
    72466,
    72468,
    72470,
    72472
  );
  script_osvdb_id(
    118175,
    118176,
    118177,
    118178,
    118179,
    118180
  );
  script_xref(name:"MSFT", value:"MS15-010");

  script_name(english:"MS15-010: Vulnerabilities in Windows Kernel-Mode Driver Could Allow Remote Code Execution (3036220)");
  script_summary(english:"Checks the version of Win32k.sys, adtschema.dll, wdigest.dll, and schannel.dll.");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security patch. It is, therefore,
affected by the following vulnerabilities :

  - A privilege escalation vulnerability exists in the
    Windows kernel-mode driver that is caused by improperly
    handling objects in memory. (CVE-2015-0003,
    CVE-2015-0057)

  - A security feature bypass vulnerability exists in the
    Cryptography Next Generation kernel-mode driver when
    failing to properly validate and enforce impersonation
    levels. (CVE-2015-0010)

  - A privilege escalation vulnerability exists in the
    Windows kernel-mode driver due to a double-free
    condition. (CVE-2015-0058)

  - A remote code execution vulnerability exists in the
    Windows kernel-mode driver that is caused when
    improperly handling TrueType fonts. (CVE-2015-0059)

  - A denial of service vulnerability exists in the
    Windows kernel-mode driver that is caused when the
    Windows font mapper attempts to scale a font.
    (CVE-2015-0060)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS15-010");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2003, Vista, 2008,
7, 2008 R2, 8, 2012, 8.1, and 2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS15-010';

kbs = make_list(
  "3013455",
  "3023562",
  "3036220"
);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2003:'2', vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

# The 2k3 checks could flag XP 64, which is unsupported
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows XP" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

if (
  # Windows 8.1 / 2012 R2
  hotfix_is_vulnerable(os:"6.3", file:"win32k.sys", version:"6.3.9600.17630", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3013455") ||
  hotfix_is_vulnerable(os:"6.3", file:"Adtschema.dll", version:"6.3.9600.17415", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3023562") ||

  # Windows 8 / 2012
  hotfix_is_vulnerable(os:"6.2", file:"win32k.sys", version:"6.2.9200.21343", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:"3013455") ||
  hotfix_is_vulnerable(os:"6.2", file:"win32k.sys", version:"6.2.9200.17226", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3013455") ||
  hotfix_is_vulnerable(os:"6.2", file:"wdigest.dll", version:"6.2.9200.21012", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:"3023562") ||
  hotfix_is_vulnerable(os:"6.2", file:"wdigest.dll", version:"6.2.9200.16891", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3023562") ||

  # Windows 7 / 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"win32k.sys", version:"6.1.7601.22919", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:"3013455") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"win32k.sys", version:"6.1.7601.18713", min_version:"6.1.7600.18000", dir:"\system32", bulletin:bulletin, kb:"3013455") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"schannel.dll", version:"6.1.7601.22925", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:"3023562") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"schannel.dll", version:"6.1.7601.18606", min_version:"6.1.7600.18000", dir:"\system32", bulletin:bulletin, kb:"3023562") ||

  # Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"win32k.sys", version:"6.0.6002.23588", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3013455") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"win32k.sys", version:"6.0.6002.19279", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3013455") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"schannel.dll", version:"6.0.6002.23594", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3023562") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"schannel.dll", version:"6.0.6002.19247", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3023562") ||

  # Windows 2003
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"win32k.sys", version:"5.2.3790.5513", dir:"\system32", bulletin:bulletin, kb:"3013455") ||
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"schannel.dll", version:"5.2.3790.5516", dir:"\system32", bulletin:bulletin, kb:"3023562")

)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
