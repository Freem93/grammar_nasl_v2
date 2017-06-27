#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93963);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/14 17:43:16 $");

  script_cve_id(
    "CVE-2016-3267",
    "CVE-2016-3331",
    "CVE-2016-3382",
    "CVE-2016-3386",
    "CVE-2016-3387",
    "CVE-2016-3388",
    "CVE-2016-3389",
    "CVE-2016-3390",
    "CVE-2016-3391",
    "CVE-2016-3392",
    "CVE-2016-7189",
    "CVE-2016-7190",
    "CVE-2016-7194"
  );
  script_bugtraq_id(
    93376,
    93379,
    93381,
    93382,
    93383,
    93386,
    93387,
    93398,
    93399,
    93401,
    93426,
    93427,
    93428
  );
  script_osvdb_id(
    145494,
    145495,
    145496,
    145500,
    145501,
    145502,
    145503,
    145504,
    145505,
    145506,
    145507,
    145508,
    145509
  );
  script_xref(name:"MSFT", value:"MS16-119");

  script_name(english:"MS16-119: Cumulative Security Update for Microsoft Edge (3192890)");
  script_summary(english:"Checks the file version of edgehtml.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web browser installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is
missing Cumulative Security Update 3192890. It is, therefore, affected
by multiple vulnerabilities, including remote code execution
vulnerabilities. An unauthenticated, remote attacker can exploit these
vulnerabilities by convincing a user to visit a specially crafted
website, resulting in the execution of arbitrary code in the context
of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-119");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
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
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS16-119';
kbs = make_list('3192440', '3192441', '3194798');

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

# Server core is not affected
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"10", sp:0, file:"edgehtml.dll", version:"11.0.14393.321", os_build:"14393", dir:"\system32", bulletin:bulletin, kb:"3194798") ||
  hotfix_is_vulnerable(os:"10", sp:0, file:"edgehtml.dll", version:"11.0.10586.633", os_build:"10586", dir:"\system32", bulletin:bulletin, kb:"3192441") ||
  hotfix_is_vulnerable(os:"10", arch:"x86", sp:0, file:"edgehtml.dll", version:"11.0.10240.17146", os_build:"10240", dir:"\system32", bulletin:bulletin, kb:"3192440") ||
  hotfix_is_vulnerable(os:"10", arch:"x64", sp:0, file:"edgehtml.dll", version:"11.0.10240.17113", os_build:"10240", dir:"\system32", bulletin:bulletin, kb:"3192440")
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
