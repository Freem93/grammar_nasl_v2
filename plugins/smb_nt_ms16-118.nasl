#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94011);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/05/24 14:05:10 $");

  script_cve_id(
    "CVE-2016-3267",
    "CVE-2016-3298",
    "CVE-2016-3331",
    "CVE-2016-3382",
    "CVE-2016-3383",
    "CVE-2016-3384",
    "CVE-2016-3385",
    "CVE-2016-3387",
    "CVE-2016-3388",
    "CVE-2016-3390",
    "CVE-2016-3391"
  );
  script_bugtraq_id(
    93376,
    93379,
    93381,
    93382,
    93383,
    93386,
    93387,
    93392,
    93393,
    93396,
    93397
  );
  script_osvdb_id(
    145493,
    145494,
    145495,
    145496,
    145497,
    145498,
    145499,
    145500,
    145501,
    145502,
    145503
  );
  script_xref(name:"MSFT", value:"MS16-118");
  script_xref(name:"IAVB", value:"2016-B-0150");

  script_name(english:"MS16-118: Cumulative Security Update for Internet Explorer (3192887)");
  script_summary(english:"Checks the version of mshtml.dll or the installed rollup.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web browser installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Internet Explorer installed on the remote Windows host
is missing Cumulative Security Update 3192887. It is, therefore,
affected by multiple vulnerabilities, the majority of which are remote
code execution vulnerabilities. An unauthenticated, remote attacker
can exploit these vulnerabilities by convincing a user to visit a
specially crafted website, resulting in the execution of arbitrary
code in the context of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-118");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Internet Explorer 9, 10,
and 11.

Note that security update 3193515 in MS16-126 must also be installed
in order to fully resolve CVE-2016-3298 on Windows Vista and Windows
Server 2008.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "smb_check_rollup.nasl");
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

bulletin = 'MS16-118';
kbs = make_list(
  '3185330',
  '3185331',
  '3185332',
  '3191492',
  '3192391',
  '3192392',
  '3192393',
  '3192440',
  '3192441',
  '3194798'
);

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
  # Windows 10 1607
  smb_check_rollup(os:"10", sp:0, os_build:"14393", rollup_date: "10_2016", bulletin:bulletin, rollup_kb_list:make_list(3194798)) ||
  # Windows 10 1511
  smb_check_rollup(os:"10", sp:0, os_build:"10586", rollup_date: "10_2016", bulletin:bulletin, rollup_kb_list:make_list(3192441)) ||
  # Windows 10
  smb_check_rollup(os:"10", sp:0, os_build:"10240", rollup_date: "10_2016", bulletin:bulletin, rollup_kb_list:make_list(3192440)) ||

  # Windows 8.1 / Windows Server 2012 R2
  # Internet Explorer 11
  smb_check_rollup(os:"6.3", sp:0, rollup_date: "10_2016", bulletin:bulletin, rollup_kb_list:make_list(3192392, 3185331)) ||

  # Windows Server 2012
  # Internet Explorer 10
  smb_check_rollup(os:"6.2", sp:0, rollup_date: "10_2016", bulletin:bulletin, rollup_kb_list:make_list(3192393, 3185332)) ||

  # Windows 7 / Server 2008 R2
  # Internet Explorer 11
  smb_check_rollup(os:"6.1", sp:1, rollup_date: "10_2016", bulletin:bulletin, rollup_kb_list:make_list(3192391, 3185330)) ||

  # Vista / Windows Server 2008
  # Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.20947", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:"3191492") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.16830", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"3191492")
)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}
