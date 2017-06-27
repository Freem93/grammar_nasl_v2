#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97729);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/05/26 23:57:36 $");

  script_cve_id(
    "CVE-2017-0008",
    "CVE-2017-0009",
    "CVE-2017-0012",
    "CVE-2017-0018",
    "CVE-2017-0033",
    "CVE-2017-0037",
    "CVE-2017-0040",
    "CVE-2017-0049",
    "CVE-2017-0059",
    "CVE-2017-0130",
    "CVE-2017-0149",
    "CVE-2017-0154"
  );
  script_bugtraq_id(
    96073,
    96077,
    96085,
    96086,
    96087,
    96088,
    96094,
    96095,
    96645,
    96647,
    96724,
    96766
  );
  script_osvdb_id(
    152481,
    153622,
    153623,
    153624,
    153625,
    153626,
    153627,
    153628,
    153629,
    153630,
    153631,
    153632
  );
  script_xref(name:"MSFT", value:"MS17-006");
  script_xref(name:"MSKB", value:"3218362");
  script_xref(name:"MSKB", value:"4012204");
  script_xref(name:"MSKB", value:"4012215");
  script_xref(name:"MSKB", value:"4012216");
  script_xref(name:"MSKB", value:"4012217");
  script_xref(name:"MSKB", value:"4012606");
  script_xref(name:"MSKB", value:"4013198");
  script_xref(name:"MSKB", value:"4013429");

  script_name(english:"MS17-006: Cumulative Security Update for Internet Explorer (4013073)");
  script_summary(english:"Checks the version of mshtml.dll or the installed rollup.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web browser installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Internet Explorer installed on the remote Windows host
is missing Cumulative Security Update 4013073. It is, therefore,
affected by multiple vulnerabilities, the most severe of which are
remote code execution vulnerabilities. An unauthenticated, remote
attacker can exploit these vulnerabilities by convincing a user to
visit a specially crafted website, resulting in the execution of
arbitrary code in the context of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms17-006");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Internet Explorer 9, 10,
and 11.

Note that security update 3218362 in MS17-006 must also be installed
in order to fully resolve CVE-2017-0008 on Windows Vista and Windows
Server 2008.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
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
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS17-006';
kbs = make_list(
  '4012204', # ie9 ; vista and 2008
  '3218362', # ie9 ; api messaging ; vista and 2008
  '4012204', # ie10 sec rollup ; 2012
  '4012217', # ie10 reg rollup ; 2012
  '4012204', # ie11 sec rollup ; 7 and 2008 r2
  '4012215', # ie11 reg rollup ; 7 and 2008 r2
  '4012204', # ie11 sec rollup ; 8.1 and 2012 r2
  '4012216', # ie11 reg rollup ; 8.1 and 2012 r2
  '4012606', # ie11 rollup ; win 10
  '4013198', # ie11 rollup ; win 10 1511
  '4013429'  # ie11 rollup ; win 10 1607
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
  smb_check_rollup(os:"10", sp:0, os_build:"14393", rollup_date: "03_2017", bulletin:bulletin, rollup_kb_list:make_list(4013429)) ||
  # Windows 10 1511
  smb_check_rollup(os:"10", sp:0, os_build:"10586", rollup_date: "03_2017", bulletin:bulletin, rollup_kb_list:make_list(4013198)) ||
  # Windows 10
  smb_check_rollup(os:"10", sp:0, os_build:"10240", rollup_date: "03_2017", bulletin:bulletin, rollup_kb_list:make_list(4012606)) ||

  # Windows 8.1 / Windows Server 2012 R2
  # Internet Explorer 11
  smb_check_rollup(os:"6.3", sp:0, rollup_date: "03_2017", bulletin:bulletin, rollup_kb_list:make_list(4012204, 4012216)) ||

  # Windows Server 2012
  # Internet Explorer 10
  smb_check_rollup(os:"6.2", sp:0, rollup_date: "03_2017", bulletin:bulletin, rollup_kb_list:make_list(4012204, 4012217)) ||

  # Windows 7 / Server 2008 R2
  # Internet Explorer 11
  smb_check_rollup(os:"6.1", sp:1, rollup_date: "03_2017", bulletin:bulletin, rollup_kb_list:make_list(4012204, 4012215)) ||

  # Vista / Windows Server 2008
  # Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.20985", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:"4012204") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.16871", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"4012204") ||

  # KB 3218362 / Vista and Windows Server 2008 / Inetcomm.dll
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"inetcomm.dll", version:"6.0.6002.24052", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3218362") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"inetcomm.dll", version:"6.0.6002.19728", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3218362")
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
