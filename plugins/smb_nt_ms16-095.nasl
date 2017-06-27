#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92819);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/09 21:04:54 $");

  script_cve_id(
    "CVE-2016-3288",
    "CVE-2016-3289",
    "CVE-2016-3290",
    "CVE-2016-3293",
    "CVE-2016-3321",
    "CVE-2016-3322",
    "CVE-2016-3326",
    "CVE-2016-3327",
    "CVE-2016-3329"
  );
  script_bugtraq_id(
    92282,
    92284,
    92285,
    92286,
    92287,
    92291,
    92305,
    92321,
    92322
  );
  script_osvdb_id(
    142717,
    142718,
    142719,
    142720,
    142721,
    142722,
    142723,
    142724,
    142725
  );
  script_xref(name:"MSFT", value:"MS16-095");

  script_name(english:"MS16-095: Cumulative Security Update for Internet Explorer (3177356)");
  script_summary(english:"Checks the version of mshtml.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web browser installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Internet Explorer installed on the remote Windows host
is missing Cumulative Security Update 3177356. It is, therefore,
affected by multiple vulnerabilities, the majority of which are remote
code execution vulnerabilities. An unauthenticated, remote attacker
can exploit these vulnerabilities by convincing a user to visit a
specially crafted website, resulting in the execution of arbitrary
code in the context of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/security/MS16-095");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Internet Explorer 9, 10,
and 11.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/09");

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

bulletin = 'MS16-095';
kbs = make_list('3175443', '3176492', '3176493', '3176495');

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
  hotfix_is_vulnerable(os:"10", sp:0, file:"mshtml.dll", version:"11.0.14393.51", os_build:"14393", dir:"\system32", bulletin:bulletin, kb:"3176495") ||
  hotfix_is_vulnerable(os:"10", sp:0, file:"mshtml.dll", version:"11.0.10586.545", os_build:"10586", dir:"\system32", bulletin:bulletin, kb:"3176493") ||
  hotfix_is_vulnerable(os:"10", sp:0, file:"mshtml.dll", version:"11.0.10240.17071", os_build:"10240", dir:"\system32", bulletin:bulletin, kb:"3176492") ||

  # Windows 8.1 / Windows Server 2012 R2
  # Internet Explorer 11
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"mshtml.dll", version:"11.0.9600.18427", min_version:"11.0.9600.17000", dir:"\system32", bulletin:bulletin, kb:"3175443") ||

  # Windows Server 2012
  # Internet Explorer 10
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"10.0.9200.21926", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3175443") ||

  # Windows 7 / Server 2008 R2
  # Internet Explorer 11
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"11.0.9600.18427", min_version:"11.0.9600.17000", dir:"\system32", bulletin:bulletin, kb:"3175443") ||

  # Vista / Windows Server 2008
  # Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.20927", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:"3175443") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.16811", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"3175443")
)
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
