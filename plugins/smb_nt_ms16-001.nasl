#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87877);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/04/29 19:33:20 $");

  script_cve_id("CVE-2016-0002", "CVE-2016-0005");
  script_bugtraq_id(79892, 79894);
  script_osvdb_id(132780, 132781);
  script_xref(name:"MSFT", value:"MS16-001");

  script_name(english:"MS16-001: Cumulative Security Update for Internet Explorer (3124903)");
  script_summary(english:"Checks the version of mshtml.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web browser installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Internet Explorer installed on the remote host is
missing Cumulative Security Update 3124903. It is, therefore, affected
by multiple vulnerabilities :

  - A remote code execution vulnerability exists in the
    VBScript engine due to improper handling of objects in
    memory. An attacker can exploit this vulnerability by
    convincing a user to visit a specially crafted website
    or open a Microsoft Office document containing an
    embedded ActiveX control, resulting in execution of
    arbitrary code in the context of the current user.
    (CVE-2016-0002)

  - An elevation of privilege vulnerability exists due to
    improper enforcement of cross-domain policies. An
    attacker can exploit this vulnerability to access
    information from one domain and inject it into another
    domain, resulting in a bypass of the cross-origin
    policy and an elevation of privileges. (CVE-2016-0005)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-001");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 8, RT, 2012, 8.1, RT 8.1, 2012 R2, and 10.

Note that Windows 10 with Citrix XenDesktop installed will not be
offered the patch due to an issue with the XenDesktop software that
prevents users from logging on when the patch is applied. To apply the
patch you must first uninstall XenDesktop or contact Citrix for help
with the issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
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
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS16-001';
kbs = make_list('3124275', '3124266', '3124263');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 10
  hotfix_is_vulnerable(os:"10", sp:0, file:"mshtml.dll", version:"11.0.10586.35", min_version:"11.0.10586.0", dir:"\system32", bulletin:bulletin, kb:"3124263") ||
  hotfix_is_vulnerable(os:"10", sp:0, file:"mshtml.dll", version:"11.0.10240.16644", min_version:"11.0.10240.16000", dir:"\system32", bulletin:bulletin, kb:"3124266") ||

  # Windows 8.1 / Windows Server 2012 R2
  # Internet Explorer 11
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"mshtml.dll", version:"11.0.9600.18161", min_version:"11.0.9600.17000", dir:"\system32", bulletin:bulletin, kb:"3124275") ||

  # Windows 8 / Windows Server 2012
  # Internet Explorer 10
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"10.0.9200.21726", min_version:"10.0.9200.21000", dir:"\system32", bulletin:bulletin, kb:"3124275") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"10.0.9200.17606", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3124275") ||

  # Windows 7 / Server 2008 R2
  # Internet Explorer 11
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"11.0.9600.18163", min_version:"11.0.9600.17000", dir:"\system32", bulletin:bulletin, kb:"3124275") ||
  # Internet Explorer 10
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"10.0.9200.21728", min_version:"10.0.9200.21000", dir:"\system32", bulletin:bulletin, kb:"3124275") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"10.0.9200.17606", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3124275") ||
  # Internet Explorer 9
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"9.0.8112.20852", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:"3124275") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"9.0.8112.16737", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"3124275") ||
  # Internet Explorer 8
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"8.0.7601.23301", min_version:"8.0.7601.22000", dir:"\system32", bulletin:bulletin, kb:"3124275") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"8.0.7601.19104", min_version:"8.0.7601.17000", dir:"\system32", bulletin:bulletin, kb:"3124275") ||

  # Vista / Windows Server 2008
  # Internet Explorer 7
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"7.0.6002.23878", min_version:"7.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3124275") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"7.0.6002.19567", min_version:"7.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3124275") ||
  # Internet Explorer 8
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"8.0.6001.23786", min_version:"8.0.6001.23000", dir:"\system32", bulletin:bulletin, kb:"3124275") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"8.0.6001.19727", min_version:"8.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:"3124275") ||
  # Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.20852", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:"3124275") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.16737", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"3124275")
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
