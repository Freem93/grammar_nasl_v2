#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88642);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/09 21:04:54 $");

  script_cve_id(
    "CVE-2016-0041",
    "CVE-2016-0059",
    "CVE-2016-0060",
    "CVE-2016-0061",
    "CVE-2016-0062",
    "CVE-2016-0063",
    "CVE-2016-0064",
    "CVE-2016-0067",
    "CVE-2016-0068",
    "CVE-2016-0069",
    "CVE-2016-0071",
    "CVE-2016-0072",
    "CVE-2016-0077"
  );
  script_bugtraq_id(
    82505,
    82629,
    82650,
    82653,
    82658,
    82659,
    82661,
    82662,
    82663,
    82664,
    82665,
    82669,
    82671
  );
  script_osvdb_id(
    134291,
    134292,
    134293,
    134294,
    134295,
    134296,
    134297,
    134298,
    134299,
    134300,
    134301,
    134302,
    134303
  );
  script_xref(name:"MSFT", value:"MS16-009");

  script_name(english:"MS16-009: Cumulative Security Update for Internet Explorer (3134220)");
  script_summary(english:"Checks the version of mshtml.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web browser installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Internet Explorer installed on the remote host is
missing Cumulative Security Update 3134220. It is, therefore, affected
by multiple vulnerabilities :

  - A remote code execution vulnerability exists due to
    improper validation of input when loading dynamic link
    library (DLL) files. A local attacker can exploit this,
    via a specially crafted application, to execute
    arbitrary code. (CVE-2016-0041)

  - An information disclosure vulnerability exists in the
    Hyperlink Object Library due to improper handling of
    objects in memory. A remote attacker can exploit this by
    convincing a user to click a link in an email or Office
    file, resulting in the disclosure of memory contents.
    (CVE-2016-0059)

  - Multiple remote code execution vulnerabilities exist due
    to improper handling of objects in memory. A remote 
    attacker can exploit these vulnerabilities by convincing
    a user to visit a specially crafted website, resulting
    in the execution of arbitrary code in the context of the
    current user. (CVE-2016-0060, CVE-2016-0061,
    CVE-2016-0062, CVE-2016-0063, CVE-2016-0064,
    CVE-2016-0067, CVE-2016-0071, CVE-2016-0072)

  - A spoofing vulnerability exists due to improper parsing
    of HTTP responses. An unauthenticated, remote attacker
    can exploit this, via a specially crafted URL, to
    redirect a user to a malicious website. (CVE-2016-0077)

  - Multiple elevation of privilege vulnerabilities exist
    due to improper enforcement of cross-domain policies. An
    unauthenticated, remote attacker can exploit this by
    convincing a user to visit a specially crafted website,
    resulting in an elevation of privilege. (CVE-2016-0068,
    CVE-2016-0069)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/security/MS16-009");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Office OLE Multiple DLL Side Loading Vulnerabilities');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/09");

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

bulletin = 'MS16-009';
kbs = make_list('3134814', '3141092', '3135174', '3135173');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0',  win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "8.1" >!< productname)
 audit(AUDIT_OS_SP_NOT_VULN);

if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 10
  hotfix_is_vulnerable(os:"10", sp:0, file:"mshtml.dll", version:"11.0.10586.103", min_version:"11.0.10586.0", dir:"\system32", bulletin:bulletin, kb:"3135173") ||
  hotfix_is_vulnerable(os:"10", sp:0, file:"mshtml.dll", version:"11.0.10240.16683", min_version:"11.0.10240.16000", dir:"\system32", bulletin:bulletin, kb:"3135174") ||

  # Windows 8.1 / Windows Server 2012 R2
  # Internet Explorer 11
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"mshtml.dll", version:"11.0.9600.18212", min_version:"11.0.9600.17000", dir:"\system32", bulletin:bulletin, kb:"3141092") ||
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"mshtml.dll", version:"11.0.9600.18205", min_version:"11.0.9600.17000", dir:"\system32", bulletin:bulletin, kb:"3134814") ||

  # Windows Server 2012
  # Internet Explorer 10
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"10.0.9200.21759", min_version:"10.0.9200.21000", dir:"\system32", bulletin:bulletin, kb:"3134814") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"10.0.9200.17640", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3134814") ||

  # Windows 7 / Server 2008 R2
  # Internet Explorer 11
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"11.0.9600.18212", min_version:"11.0.9600.17000", dir:"\system32", bulletin:bulletin, kb:"3141092") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"11.0.9600.18205", min_version:"11.0.9600.17000", dir:"\system32", bulletin:bulletin, kb:"3134814") ||

  # Vista / Windows Server 2008
  # Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.20863", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:"3134814") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.16748", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"3134814")
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
