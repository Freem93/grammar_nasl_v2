#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93466);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/03/21 03:23:57 $");

  script_cve_id(
    "CVE-2016-3348",
    "CVE-2016-3349",
    "CVE-2016-3354",
    "CVE-2016-3355",
    "CVE-2016-3356"
  );
  script_bugtraq_id(
    92782,
    92783,
    92784,
    92787,
    92792
  );
  script_osvdb_id(
    144161,
    144162,
    144163,
    144164,
    144165
  );
  script_xref(name:"MSFT", value:"MS16-106");
  script_xref(name:"IAVA", value:"2016-A-0240");

  script_name(english:"MS16-106: Security Update for Microsoft Graphics Component (3185848)");
  script_summary(english:"Checks the version of win32k.sys.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple vulnerabilities :

  - Multiple elevation of privilege vulnerabilities exist in
    Windows kernel-mode drivers due to improper handling of
    objects in memory. An authenticated, remote attacker can
    exploit these, via a specially crafted application, to
    run arbitrary code in kernel mode. (CVE-2016-3348,
    CVE-2016-3349)

  - An information disclosure vulnerability exists in the
    Graphics Device Interface (GDI) due to improper handling
    of objects in memory. An authenticated, remote attacker
    can exploit this, via a specially crafted application,
    to circumvent the Address Space Layout Randomization
    (ASLR) feature and disclose sensitive memory
    information. (CVE-2016-3354)

  - An elevation of privilege vulnerability exists in the
    Graphics Device Interface (GDI) due to improper handling
    of objects in memory. An authenticated, remote attacker
    can exploit this to run arbitrary code in kernel mode.
    (CVE-2016-3355)

  - An unspecified flaw exists in the Graphics Device
    Interface (GDI) due to improper handling of objects in
    memory. An unauthenticated, remote attacker can exploit
    this, by convincing a user to visit a specially crafted
    website or open a malicious document, to execute
    arbitrary code in the context of the current user.
    (CVE-2016-3356");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/security/MS16-106");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS16-106';
kbs = make_list(
  "3185911", # Else
  "3185611", # Win 10
  "3185614", # Win 10 T2 1511
  "3189866"  # Win 10 T3 1607
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "8.1" >!< productname)
  audit(AUDIT_OS_SP_NOT_VULN);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);


if (
  # 10 threshold 3 (aka 1607)
  hotfix_is_vulnerable(os:"10", sp:0, file:"win32kfull.sys", version:"10.0.14393.187", os_build:"14393", dir:"\system32", bulletin:bulletin, kb:"3189866") ||

  # 10 threshold 2 (aka 1511)
  hotfix_is_vulnerable(os:"10", sp:0, file:"win32kfull.sys", version:"10.0.10586.589", os_build:"10586", dir:"\system32", bulletin:bulletin, kb:"3185614") ||

  # 10 RTM
  hotfix_is_vulnerable(os:"10", sp:0, file:"win32kfull.sys", version:"10.0.10240.17113", os_build:"10240", dir:"\system32", bulletin:bulletin, kb:"3185611") ||

  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"win32k.sys", version:"6.3.9600.18439", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3185911") ||

  # Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"win32k.sys", version:"6.2.9200.21966", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3185911") ||

  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"win32k.sys", version:"6.1.7601.23528", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:"3185911") ||

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"win32k.sys", version:"6.0.6002.24008", min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:"3185911") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"win32k.sys", version:"6.0.6002.19681", min_version:"6.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:"3185911")
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

