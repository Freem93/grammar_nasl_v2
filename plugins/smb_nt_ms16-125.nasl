#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94008);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/05/24 14:05:10 $");

  script_cve_id("CVE-2016-7188");
  script_bugtraq_id(93359);
  script_osvdb_id(145402);
  script_xref(name:"MSFT", value:"MS16-125");
  script_xref(name:"IAVB", value:"2016-B-0151");

  script_name(english:"MS16-125: Security Update for Windows Diagnostic Hub (3193229)");
  script_summary(english:"Checks for the October 2016 Rollup.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by an elevation of privilege
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by an elevation of privilege vulnerability in the
Windows Diagnostics Hub Standard Collector service due to improper
sanitization of user-supplied input. A local attacker can exploit
this, via a specially crafted application, to execute arbitrary code
with elevated system privileges.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-125");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 10.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/12");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:microsoft:windows");
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
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS16-125';
kbs = make_list("3192440", "3192441", "3194798");

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:"MS16-125", kbs:kbs, severity:SECURITY_HOLE);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 10" >!< productname) audit(AUDIT_OS_SP_NOT_VULN);

if (
  # 10 threshold 3 (aka 1607)
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"14393",
                   rollup_date: "10_2016",
                   bulletin:bulletin,
                   rollup_kb_list:make_list(3194798)) ||
  # 10 threshold 2 (aka 1511)
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"10586",
                   rollup_date: "10_2016",
                   bulletin:bulletin,
                   rollup_kb_list:make_list(3192441)) ||
  # 10 RTM
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"10240",
                   rollup_date: "10_2016",
                   bulletin:bulletin,
                   rollup_kb_list:make_list(3192440))
)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  exit(0);
}
else
{
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}
