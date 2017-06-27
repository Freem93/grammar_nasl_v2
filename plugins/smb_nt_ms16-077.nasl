#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91605);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/08/10 19:29:29 $");

  script_cve_id("CVE-2016-3213", "CVE-2016-3236", "CVE-2016-3299");
  script_bugtraq_id(91111, 91114, 92387);
  script_osvdb_id(139954, 139968, 142754);
  script_xref(name:"MSFT", value:"MS16-077");
  script_xref(name:"IAVA", value:"2016-A-0157");

  script_name(english:"MS16-077: Security Update for WPAD (3165191)");
  script_summary(english:"Checks the version of mswsock.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple elevation of privilege
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple elevation of privilege
vulnerabilities :

  - An elevation of privilege vulnerability exists in the
    Web Proxy Auto Discovery (WPAD) protocol due to improper
    handling of the proxy discovery process. A remote
    attacker can exploit this, by responding to NetBIOS name
    requests for WPAD, to bypass security restrictions and
    gain elevated privileges. (CVE-2016-3213)

  - An elevation of privilege vulnerability exists in the
    Web Proxy Auto Discovery (WPAD) protocol due to improper
    handling of certain proxy discovery scenarios. A remote
    attacker can exploit this to elevate privileges,
    resulting in the ability to disclose or control network
    traffic. (CVE-2016-3236)

  - An elevation of privilege vulnerability exists in
    NetBIOS due to improper handling of responses. A remote
    attacker can exploit this, via specially crafted NetBIOS
    responses, to appear as a trusted network device,
    resulting in the ability to render untrusted content in
    a browser outside of Enhanced Protected Mode (EPM) or an
    application container. (CVE-2016-3299)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-077");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 8, 2012, 8.1, RT 8.1, 2012 R2, and 10.

Note that cumulative update 3160005 in MS16-063 must also be installed
in order to fully resolve CVE-2016-3213.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

bulletin = 'MS16-077';
kbs = make_list('3163017', '3161949', '3163018');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if(hotfix_check_sp_range(win10:'0', vista:'2', win7:'1', win8:'0', win81:'0') <= 0)
  audit(AUDIT_OS_SP_NOT_VULN);
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "Windows 8.1" >!< productname)
  audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"ws2_32.dll", version:"6.3.9600.18340", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3161949") ||

  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"ws2_32.dll", version:"6.2.9200.21858", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3161949") ||

  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"ws2_32.dll", version:"6.1.7601.23451", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:"3161949") ||

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"ws2_32.dll", version:"6.0.6002.23970", min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:"3161949") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"ws2_32.dll", version:"6.0.6002.19655", min_version:"6.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:"3161949") ||

  # Windows 10
  hotfix_is_vulnerable(os:"10", sp:0, file:"ws2_32.dll", version:"10.0.10240.16942", min_version:"10.0.10240.0", dir:"\system32", bulletin:bulletin, kb:"3163017") ||
  hotfix_is_vulnerable(os:"10", sp:0, file:"ws2_32.dll", version:"10.0.10586.420", min_version:"10.0.10586.0", dir:"\system32", bulletin:bulletin, kb:"3163018")
)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
