#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(85332);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/06/10 20:57:24 $");

  script_cve_id(
    "CVE-2015-2472",
    "CVE-2015-2473"
  );
  script_bugtraq_id(
    76224,
    76228
  );
  script_osvdb_id(
    125987,
    125988
  );
  script_xref(name:"MSFT", value:"MS15-082");
  script_xref(name:"IAVA", value:"2015-A-0190");

  script_name(english:"MS15-082: Vulnerability in RDP Could Allow Remote Code Execution (3080348)");
  script_summary(english:"Checks the version of rdpcorets.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is, therefore
affected by the following vulnerabilities :

  - A spoofing vulnerability exists due to the Remote
    Desktop Session Host (RDSH) not properly validating
    certificates during authentication. An man-in-the-middle
    attacker can exploit this to impersonate a client
    session by spoofing a TLS/SSL server via a certificate
    that appears valid. (CVE-2015-2472)

  - A code execution vulnerability exists due to the Remote
    Desktop Protocol client not properly handling the
    loading of certain specially crafted DLL files. An
    attacker, by placing a malicious DLL in the user's
    current working directory and convincing the user to
    open a crafted RDP file, can exploit this issue to
    execute arbitrary code in the context of the user.
    (CVE-2015-2473)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-082");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 8, 8.1, 2012, 2012 R2, RT, and RT 8.1.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS15-082';

kbs = make_list(
  "3075220",
  "3075221",
  "3075222",
  "3075226"
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8.1 / 2012 R2
  hotfix_is_vulnerable(os:"6.3", file:"mstscax.dll", version:"6.3.9600.17931", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3075220") ||
  hotfix_is_vulnerable(os:"6.3", file:"aaedge.dll", version:"6.3.9600.17931", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3075220") ||

  # Windows 8 / 2012
  hotfix_is_vulnerable(os:"6.2", file:"mstscax.dll", version:"6.2.9200.21544", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:"3075220") ||
  hotfix_is_vulnerable(os:"6.2", file:"mstscax.dll", version:"6.2.9200.17434", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3075220") ||

  # Windows 7 / 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mstscax.dll", version:"6.1.7601.23121", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:"3075220") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mstscax.dll", version:"6.1.7601.18918", min_version:"6.1.7600.18000", dir:"\system32", bulletin:bulletin, kb:"3075220") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"aaclient.dll", version:"6.2.9200.21545", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:"3075222") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"aaclient.dll", version:"6.2.9200.17435", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3075222") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mstscax.dll", version:"6.3.9600.17930", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3075226") ||

  # Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mstscax.dll", version:"6.0.6002.23747", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3075220") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mstscax.dll", version:"6.0.6002.19439", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3075220") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"aaclient.dll", version:"6.1.7600.17233", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:"3075221") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"aaclient.dll", version:"6.1.7600.21448", min_version:"6.1.7600.20000", dir:"\system32", bulletin:bulletin, kb:"3075221")
)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
