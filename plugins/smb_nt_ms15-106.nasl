#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86367);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/04/29 19:33:19 $");

  script_cve_id(
    "CVE-2015-2482",
    "CVE-2015-6042",
    "CVE-2015-6044",
    "CVE-2015-6045",
    "CVE-2015-6046",
    "CVE-2015-6047",
    "CVE-2015-6048",
    "CVE-2015-6049",
    "CVE-2015-6050",
    "CVE-2015-6051",
    "CVE-2015-6052",
    "CVE-2015-6053",
    "CVE-2015-6055",
    "CVE-2015-6056",
    "CVE-2015-6059",
    "CVE-2015-6184"
  );
  script_bugtraq_id(
    76982,
    76984,
    76986,
    76987,
    76991,
    76992,
    76993,
    76995,
    77000,
    77002,
    77005,
    77006,
    77007,
    77010
  );
  script_osvdb_id(
    128790,
    128791,
    128792,
    128793,
    128794,
    128795,
    128796,
    128797,
    128798,
    128799,
    128800,
    128801,
    128802,
    128803,
    129323
  );
  script_xref(name:"MSFT", value:"MS15-106");

  script_name(english:"MS15-106: Cumulative Security Update for Internet Explorer (3096441)");
  script_summary(english:"Checks the version of mshtml.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Internet Explorer installed on the remote host is
missing Cumulative Security Update 3096441. It is, therefore, affected
by multiple vulnerabilities, the majority of which are remote code
execution vulnerabilities. An unauthenticated, remote attacker can
exploit these issues by convincing a user to visit a specially crafted
website, resulting in the execution of arbitrary code in the context
of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS15-106");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 8, 2012, 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
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

bulletin = 'MS15-106';
kbs = make_list('3093983', '3105210');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 10
  hotfix_is_vulnerable(os:"10", sp:0, file:"mshtml.dll", version:"11.00.10240.16566", min_version:"11.0.10240.16000", dir:"\system32", bulletin:bulletin, kb:"3105210") ||

  # Windows 8.1 / Windows Server 2012 R2
  # Internet Explorer 11
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"mshtml.dll", version:"11.0.9600.18052", min_version:"11.0.9600.17000", dir:"\system32", bulletin:bulletin, kb:"3093983") ||

  # Windows 8 / Windows Server 2012
  # Internet Explorer 10
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"10.0.9200.21636", min_version:"10.0.9200.21000", dir:"\system32", bulletin:bulletin, kb:"3093983") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"10.0.9200.17519", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3093983") ||

  # Windows 7 / Server 2008 R2
  # Internet Explorer 10
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"10.0.9200.21636", min_version:"10.0.9200.21000", dir:"\system32", bulletin:bulletin, kb:"3093983") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"10.0.9200.17519", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3093983") ||
  # Internet Explorer 11
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"11.0.9600.18057", min_version:"11.0.9600.17000", dir:"\system32", bulletin:bulletin, kb:"3093983") ||
  # Internet Explorer 8
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"8.0.7601.23206", min_version:"8.0.7601.22000", dir:"\system32", bulletin:bulletin, kb:"3093983") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"8.0.7601.19003", min_version:"8.0.7601.17000", dir:"\system32", bulletin:bulletin, kb:"3093983") ||
  # Internet Explorer 9
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"9.0.8112.20823", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:"3093983") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"9.0.8112.16708", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"3093983") ||

  # Vista / Windows Server 2008
  # Internet Explorer 7
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"7.0.6002.23798", min_version:"7.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3093983") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"7.0.6002.19488", min_version:"7.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3093983") ||
  # Internet Explorer 8
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"8.0.6001.23750", min_version:"8.0.6001.23000", dir:"\system32", bulletin:bulletin, kb:"3093983") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"8.0.6001.19690", min_version:"8.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:"3093983") ||
  # Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.20823", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:"3093983") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.16708", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"3093983")
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
