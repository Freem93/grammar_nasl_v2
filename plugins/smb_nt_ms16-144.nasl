#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95764);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/05/24 14:05:10 $");

  script_cve_id(
    "CVE-2016-7202",
    "CVE-2016-7278",
    "CVE-2016-7279",
    "CVE-2016-7281",
    "CVE-2016-7282",
    "CVE-2016-7283",
    "CVE-2016-7284",
    "CVE-2016-7287"
  );
  script_bugtraq_id(
    94042,
    94716,
    94719,
    94722,
    94723,
    94724,
    94725,
    94726
  );
  script_osvdb_id(
    146872,
    148599,
    148600,
    148601,
    148602,
    148603,
    148604,
    148609
  );
  script_xref(name:"MSFT", value:"MS16-144");
  script_xref(name:"EDB-ID", value:"40793");

  script_name(english:"MS16-144: Cumulative Security Update for Internet Explorer (3204059)");
  script_summary(english:"Checks the version of mshtml.dll or the installed rollup.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web browser installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Internet Explorer installed on the remote Windows host
is missing Cumulative Security Update 3204059. It is, therefore,
affected by multiple vulnerabilities, the most severe of which are
remote code execution vulnerabilities. An unauthenticated, remote
attacker can exploit these vulnerabilities by convincing a user to
visit a specially crafted website, resulting in the execution of
arbitrary code in the context of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms16-144");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Internet Explorer 9, 10,
and 11.

Note that security update 3208481 in MS16-144 must also be installed
in order to fully resolve CVE-2016-7278 on Windows Vista and Windows
Server 2008.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
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
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS16-144';
kbs = make_list(
  '3203621', # ie9 ; vista and 2008
  '3208481', # ie9 ; hyperlink object ; vista and 2008
  '3205408', # ie10 sec rollup ; 2012
  '3205409', # ie10 reg rollup ; 2012
  '3205394', # ie11 sec rollup ; 7 and 2008 r2
  '3207752', # ie11 reg rollup ; 7 and 2008 r2
  '3205400', # ie11 sec rollup ; 8.1 and 2012 r2
  '3205401', # ie11 reg rollup ; 8.1 and 2012 r2
  '3205383', # ie11 rollup ; win 10
  '3205386', # ie11 rollup ; win 10 1511
  '3206632'  # ie11 rollup ; win 10 1607
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
  smb_check_rollup(os:"10", sp:0, os_build:"14393", rollup_date: "12_2016", bulletin:bulletin, rollup_kb_list:make_list(3206632)) ||
  # Windows 10 1511
  smb_check_rollup(os:"10", sp:0, os_build:"10586", rollup_date: "12_2016", bulletin:bulletin, rollup_kb_list:make_list(3205386)) ||
  # Windows 10
  smb_check_rollup(os:"10", sp:0, os_build:"10240", rollup_date: "12_2016", bulletin:bulletin, rollup_kb_list:make_list(3205383)) ||

  # Windows 8.1 / Windows Server 2012 R2
  # Internet Explorer 11
  smb_check_rollup(os:"6.3", sp:0, rollup_date: "12_2016", bulletin:bulletin, rollup_kb_list:make_list(3205400, 3205401)) ||

  # Windows Server 2012
  # Internet Explorer 10
  smb_check_rollup(os:"6.2", sp:0, rollup_date: "12_2016", bulletin:bulletin, rollup_kb_list:make_list(3205408, 3205409)) ||

  # Windows 7 / Server 2008 R2
  # Internet Explorer 11
  smb_check_rollup(os:"6.1", sp:1, rollup_date: "12_2016", bulletin:bulletin, rollup_kb_list:make_list(3205394, 3207752)) ||

  # Vista / Windows Server 2008
  # Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.20962", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:"3203621") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.16845", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"3203621") ||

  # KB 3208481 / Vista and Windows Server 2008 / hlink.dll
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"hlink.dll", version:"6.0.6002.24043", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3208481") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"hlink.dll", version:"6.0.6002.19721", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3208481")
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
