#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97743);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/05/26 23:57:36 $");

  script_cve_id(
    "CVE-2017-0007",
    "CVE-2017-0016",
    "CVE-2017-0039",
    "CVE-2017-0057",
    "CVE-2017-0100",
    "CVE-2017-0104"
  );
  script_bugtraq_id(
    95969,
    96018,
    96024,
    96695,
    96697,
    96700
  );
  script_osvdb_id(
    151353,
    153724,
    153725,
    153726,
    153727,
    153728
  );
  script_xref(name:"CERT", value:"867968");
  script_xref(name:"IAVA", value:"2017-A-0070");
  script_xref(name:"MSFT", value:"MS17-012");
  script_xref(name:"MSKB", value:"3217587");
  script_xref(name:"MSKB", value:"4012021");
  script_xref(name:"MSKB", value:"4012212");
  script_xref(name:"MSKB", value:"4012215");
  script_xref(name:"MSKB", value:"4012213");
  script_xref(name:"MSKB", value:"4012216");
  script_xref(name:"MSKB", value:"4012214");
  script_xref(name:"MSKB", value:"4012217");
  script_xref(name:"MSKB", value:"4012606");
  script_xref(name:"MSKB", value:"4013198");

  script_name(english:"MS17-012: Security Update for Microsoft Windows (4013078)");
  script_summary(english:"Checks the file versions and rollups.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple vulnerabilities :

  - A security feature bypass vulnerability exists in Device
    Guard due to improper validation of certain elements in
    a signed PowerShell script. An unauthenticated, remote
    attacker can exploit this vulnerability to modify the
    contents of a PowerShell script without invalidating the
    signature associated with the file, allowing the
    execution of a malicious script. (CVE-2017-0007)

  - A denial of service vulnerability exists in the
    Microsoft Server Message Block 2.0 and 3.0 (SMBv2/SMBv3)
    client implementations due to improper handling of
    certain requests sent to the client. An unauthenticated,
    remote attacker can exploit this issue, via a malicious
    SMB server, to cause the system to stop responding until
    it is manually restarted. (CVE-2017-0016)

  - A remote code execution vulnerability exists due to
    using an insecure path to load certain dynamic link
    library (DLL) files. A local attacker can exploit this,
    via a specially crafted library placed in the path, to
    execute arbitrary code. (CVE-2017-0039)

  - An information disclosure vulnerability exists in
    Windows dnsclient due to improper handling of certain
    requests. An unauthenticated, remote attacker can
    exploit this, by convincing a user to visit a specially
    crafted web page, to gain access to sensitive
    information on a targeted workstation. If the target is
    a server, the attacker can also exploit this issue by
    tricking the server into sending a DNS query to a
    malicious DNS server. (CVE-2017-0057)

  - An elevation of privilege vulnerability exists in
    Helppane.exe due to a failure by an unspecified DCOM
    object, configured to run as the interactive user, to
    properly authenticate the client. An authenticated,
    remote attacker can exploit this, via a specially
    crafted application, to execute arbitrary code in
    another user's session. (CVE-2017-0100)

  - An integer overflow condition exists in the iSNS Server
    service due to improper validation of input from the
    client. An unauthenticated, remote attacker can exploit
    this issue, via a specially crafted application that
    connects and issues requests to the iSNS server, to
    execute arbitrary code in the context of the SYSTEM
    account. (CVE-2017-0104)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS17-012");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, 10, and 2016.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2017/02/01");
  script_set_attribute(attribute:"patch_publication_date",value:"2017/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/15");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

bulletin = 'MS17-012';

kbs = make_list('3217587',
                '4012021',
                '4012212',
                '4012215',
                '4012213',
                '4012216',
                '4012214',
                '4012217',
                '4012606',
                '4013198',
                '4013429');

if (get_kb_item("Host/patch_management_checks")) 
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
# Windows 8 EOL
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "8.1" >!< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"imjppdmg.exe", version:"10.0.6002.24052", min_version:"10.0.6002.20000", dir:"\system32\IME\IMEJP10", bulletin:bulletin, kb:"3217587") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"imjppdmg.exe", version:"10.0.6002.19729", min_version:"10.0.6002.16000", dir:"\system32\IME\IMEJP10", bulletin:bulletin, kb:"3217587") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"isnssrv.dll", version:"6.0.6002.24065", min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:"4012021") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"isnssrv.dll", version:"6.0.6002.19741", min_version:"6.0.6002.00000", dir:"\system32", bulletin:bulletin, kb:"4012021") ||
  # Windows 7 / Server 2008 R2 # security: 4012212, monthly: 4012215
  smb_check_rollup(os:"6.1", sp:1, rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4012212, 4012215)) ||
  # Windows Server 2012 # security: 4012214, monthly: 4012217
  smb_check_rollup(os:"6.2", sp:0, rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4012214, 4012217)) ||
  # Windows 8.1 / Windows Server 2012 R2
  smb_check_rollup(os:"6.3", sp:0, rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4012213, 4012216)) ||
  # Windows 10
  smb_check_rollup(os:"10", sp:0, os_build:"10240", rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4012606)) ||
  smb_check_rollup(os:"10", sp:0, os_build:"10586", rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4013198)) ||
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
