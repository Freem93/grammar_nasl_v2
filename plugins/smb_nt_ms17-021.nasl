#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97736);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/05/26 23:57:36 $");

  script_cve_id("CVE-2017-0042");
  script_bugtraq_id(96098);
  script_osvdb_id(153672);
  script_xref(name:"MSFT", value:"MS17-021");
  script_xref(name:"MSKB", value:"3214051");
  script_xref(name:"MSKB", value:"4012212");
  script_xref(name:"MSKB", value:"4012215");
  script_xref(name:"MSKB", value:"4012213");
  script_xref(name:"MSKB", value:"4012216");
  script_xref(name:"MSKB", value:"4015548");
  script_xref(name:"MSKB", value:"4015551");
  script_xref(name:"MSKB", value:"4012606");
  script_xref(name:"MSKB", value:"4013198");
  script_xref(name:"MSKB", value:"4013429");
  script_xref(name:"IAVB", value:"2017-B-0031");

  script_name(english:"MS17-021: Security Update for Windows DirectShow (4010318)");
  script_summary(english:"Checks the version of Quartz.dll or the installed rollup.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by an information disclosure vulnerability in
Windows DirectShow due to improper handling of objects in memory. An
unauthenticated, remote attacker can exploit this, by convincing a
user to visit a website containing specially crafted media content, to
disclose sensitive information.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms17-021");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, 10, and 2016.

Note that the Microsoft Bulletin contains contradictory information
regarding the Windows 2012 Security Only Update and the Windows 2012
Monthly Rollup Update. These updates may not resolve the
vulnerability. Please contact Microsoft for clarification if you are
running Windows 2012.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:directshow");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "smb_check_rollup.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS17-021';
kbs = make_list(
  '3214051', # Vista / 2008
  '4012212', # 7 / 2008 R2 Security Only
  '4012215', # 7 / 2008 R2  Monthly Rollup
  '4012213', # 8.1 / 2012 R2 Security Only
  '4012216', # 8.1 / 2012 R2 / RT 8.1 Monthly Rollup
  '4015548', # 2012 Security Only
  '4015551', # 2012 Monthly Rollup
  '4012606', # 10 1507
  '4013198', # 10 1511
  '4013429' # 10 1607 / 2016
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# Server Core not affected
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

# Windows 8 EOL
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "8.1" >!< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Quartz.dll", version:"6.6.6002.19725", min_version:"6.6.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3214051") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Quartz.dll", version:"6.6.6002.24048", min_version:"6.6.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3214051") ||

   # 8.1 / 2012 R2 / RT 8.1
  smb_check_rollup(os:"6.3",
                   sp:0,
                   rollup_date: "03_2017",
                   bulletin:bulletin,
                   rollup_kb_list:make_list(4012213, 4012216)) ||
  # 2012
  # MS Updates on 4/11/17 superceded the old KBs for 2012
  # Hence using rollup date 04_2017
  smb_check_rollup(os:"6.2",
                   sp:0,
                   rollup_date: "04_2017",
                   bulletin:bulletin,
                   rollup_kb_list:make_list(4015548, 4015551)) ||
  # 7 / 2008 R2
  smb_check_rollup(os:"6.1",
                   sp:1,
                   rollup_date: "03_2017",
                   bulletin:bulletin,
                   rollup_kb_list:make_list(4012212, 4012215)) ||
  # 10 (1507)
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"10240",
                   rollup_date: "03_2017",
                   bulletin:bulletin,
                   rollup_kb_list:make_list(4012606)) ||
  # 10 (1511)
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"10586",
                   rollup_date: "03_2017",
                   bulletin:bulletin,
                   rollup_kb_list:make_list(4013198)) ||
  # 10 (1607)
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"14393",
                   rollup_date: "03_2017",
                   bulletin:bulletin,
                   rollup_kb_list:make_list(4013429))
)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}
