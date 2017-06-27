#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97730);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/05/26 23:57:36 $");

  script_cve_id(
    "CVE-2017-0009",
    "CVE-2017-0010",
    "CVE-2017-0011",
    "CVE-2017-0012",
    "CVE-2017-0015",
    "CVE-2017-0017",
    "CVE-2017-0023",
    "CVE-2017-0032",
    "CVE-2017-0033",
    "CVE-2017-0034",
    "CVE-2017-0035",
    "CVE-2017-0037",
    "CVE-2017-0065",
    "CVE-2017-0066",
    "CVE-2017-0067",
    "CVE-2017-0068",
    "CVE-2017-0069",
    "CVE-2017-0070",
    "CVE-2017-0071",
    "CVE-2017-0094",
    "CVE-2017-0131",
    "CVE-2017-0132",
    "CVE-2017-0133",
    "CVE-2017-0134",
    "CVE-2017-0135",
    "CVE-2017-0136",
    "CVE-2017-0137",
    "CVE-2017-0138",
    "CVE-2017-0140",
    "CVE-2017-0141",
    "CVE-2017-0150",
    "CVE-2017-0151"
  );
  script_bugtraq_id(
    96059,
    96064,
    96075,
    96077,
    96078,
    96079,
    96080,
    96082,
    96085,
    96087,
    96088,
    96648,
    96649,
    96650,
    96653,
    96655,
    96656,
    96662,
    96671,
    96681,
    96682,
    96683,
    96684,
    96685,
    96686,
    96687,
    96688,
    96689,
    96690,
    96725,
    96727,
    96786
  );
  script_osvdb_id(
    152481,
    153623,
    153624,
    153625,
    153633,
    153634,
    153635,
    153636,
    153637,
    153638,
    153639,
    153640,
    153641,
    153642,
    153643,
    153644,
    153645,
    153646,
    153647,
    153648,
    153649,
    153650,
    153651,
    153652,
    153653,
    153654,
    153655,
    153656,
    153657,
    153658,
    153659,
    153660
  );
  script_xref(name:"MSFT", value:"MS17-007");
  script_xref(name:"MSKB", value:"4012606");
  script_xref(name:"MSKB", value:"4013198");
  script_xref(name:"MSKB", value:"4013429");

  script_name(english:"MS17-007: Cumulative Security Update for Microsoft Edge (4013071)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web browser installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is
missing Cumulative Security Update 4013071. It is, therefore, affected
by multiple vulnerabilities, including remote code execution
vulnerabilities. An unauthenticated, remote attacker can exploit these
vulnerabilities by convincing a user to visit a specially crafted
website, resulting in the execution of arbitrary code in the context
of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS17-007");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 10 and Windows
Server 2016.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

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

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS17-007';
kbs = make_list(
  '4012606', # Windows 10
  '4013198', # Windows 10 1511
  '4013429'  # Windows 10 1607
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

# Server core is not affected
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 10
  smb_check_rollup(os:"10", sp:0, os_build:"10240", rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4012606)) ||
  # Windows 10 1511
  smb_check_rollup(os:"10", sp:0, os_build:"10586", rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4013198)) ||
  # Windows 10 1607
  smb_check_rollup(os:"10", sp:0, os_build:"14393", rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4013429))
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
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}
