#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93465);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/14 17:43:16 $");

  script_cve_id(
    "CVE-2016-3247",
    "CVE-2016-3291",
    "CVE-2016-3294",
    "CVE-2016-3295",
    "CVE-2016-3297",
    "CVE-2016-3325",
    "CVE-2016-3330",
    "CVE-2016-3350",
    "CVE-2016-3351",
    "CVE-2016-3370",
    "CVE-2016-3374",
    "CVE-2016-3377"
  );
  script_bugtraq_id(
    92788,
    92789,
    92793,
    92797,
    92807,
    92828,
    92829,
    92830,
    92832,
    92834,
    92838,
    92839
  );
  script_osvdb_id(
    142754,
    142804,
    144146,
    144147,
    144149,
    144152,
    144153,
    144156,
    144157,
    144158,
    144159,
    144160
  );
  script_xref(name:"MSFT", value:"MS16-105");

  script_name(english:"MS16-105: Cumulative Security Update for Microsoft Edge (3183043)");
  script_summary(english:"Checks the file version of edgehtml.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web browser installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is
missing Cumulative Security Update 3183043. It is, therefore, affected
by multiple vulnerabilities, the majority of which are remote code
execution vulnerabilities. An unauthenticated, remote attacker can
exploit these vulnerabilities by convincing a user to visit a
specially crafted website, resulting in the execution of arbitrary
code in the context of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-105");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/13");

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

bulletin = 'MS16-105';
kbs = make_list('3185611', '3185614', '3189866');

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

# Server core is not affected
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"10", sp:0, file:"edgehtml.dll", version:"11.0.14393.187", os_build:"14393", dir:"\system32", bulletin:bulletin, kb:"3189866") ||
  hotfix_is_vulnerable(os:"10", sp:0, file:"edgehtml.dll", version:"11.0.10586.589", os_build:"10586", dir:"\system32", bulletin:bulletin, kb:"3185614") ||
  hotfix_is_vulnerable(os:"10", sp:0, file:"edgehtml.dll", version:"11.0.10240.17113", os_build:"10240", dir:"\system32", bulletin:bulletin, kb:"3185611")
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
