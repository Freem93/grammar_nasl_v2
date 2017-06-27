#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91596);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/02/06 15:09:25 $");

  script_cve_id(
    "CVE-2016-0199",
    "CVE-2016-0200",
    "CVE-2016-3202",
    "CVE-2016-3205",
    "CVE-2016-3206",
    "CVE-2016-3207",
    "CVE-2016-3210",
    "CVE-2016-3211",
    "CVE-2016-3212",
    "CVE-2016-3213"
  );
  script_bugtraq_id(
    91101,
    91102,
    91103,
    91108,
    91109,
    91110,
    91111,
    91112
  );
  script_osvdb_id(
    139944,
    139945,
    139946,
    139947,
    139948,
    139949,
    139950,
    139951,
    139953,
    139954
  );
  script_xref(name:"MSFT", value:"MS16-063");

  script_name(english:"MS16-063: Cumulative Security Update for Internet Explorer (3163649)");
  script_summary(english:"Checks the version of mshtml.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web browser installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Internet Explorer installed on the remote host is
missing Cumulative Security Update 3163649. It is, therefore, affected
by multiple vulnerabilities, the majority of which are remote code
execution vulnerabilities. An unauthenticated, remote attacker can
exploit these issues by convincing a user to visit a specially crafted
website, resulting in the execution of arbitrary code in the context
of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/security/MS16-063");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Internet Explorer 9, 10,
and 11.

Note that the security update in MS16-077 must also be installed in
order to fully resolve CVE-2016-3213.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "smb_nt_ms16-077.nasl");
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

bulletin = 'MS16-063';
kbs = make_list('3160005', '3163017', '3163018');

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

vuln = 0;

if (
  # Windows 10
  hotfix_is_vulnerable(os:"10", sp:0, file:"mshtml.dll", version:"11.0.10586.420", min_version:"11.0.10586.0", dir:"\system32", bulletin:bulletin, kb:"3163018") ||
  hotfix_is_vulnerable(os:"10", sp:0, file:"mshtml.dll", version:"11.0.10240.16942", min_version:"11.0.10240.16000", dir:"\system32", bulletin:bulletin, kb:"3163017") ||

  # Windows 8.1 / Windows Server 2012 R2
  # Internet Explorer 11
   hotfix_is_vulnerable(os:"6.3", sp:0, file:"mshtml.dll", version:"11.0.9600.18349", min_version:"11.0.9600.17000", dir:"\system32", bulletin:bulletin, kb:"3160005") ||

  # Windows Server 2012
  # Internet Explorer 10
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"10.0.9200.21860", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3160005") ||

  # Windows 7 / Server 2008 R2
  # Internet Explorer 11
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"11.0.9600.18349", min_version:"11.0.9600.17000", dir:"\system32", bulletin:bulletin, kb:"3160005") ||

  # Vista / Windows Server 2008
  # Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.20904", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:"3160005") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.16789", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"3160005")
)
  vuln++;

# To be fully protected against CVE-2016-3213 , the
# update for MS16-077 must be installed.
if (get_kb_item("SMB/Missing/MS16-077"))
{
  hotfix_add_report('\nThe remote host is missing MS16-077.');
  vuln++;
}

if (vuln)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
