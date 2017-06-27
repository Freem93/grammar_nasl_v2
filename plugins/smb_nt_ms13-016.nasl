#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64577);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/02/22 15:31:27 $");

  script_cve_id(
    "CVE-2013-1248",
    "CVE-2013-1249",
    "CVE-2013-1250",
    "CVE-2013-1251",
    "CVE-2013-1252",
    "CVE-2013-1253",
    "CVE-2013-1254",
    "CVE-2013-1255",
    "CVE-2013-1256",
    "CVE-2013-1257",
    "CVE-2013-1258",
    "CVE-2013-1259",
    "CVE-2013-1260",
    "CVE-2013-1261",
    "CVE-2013-1262",
    "CVE-2013-1263",
    "CVE-2013-1264",
    "CVE-2013-1265",
    "CVE-2013-1266",
    "CVE-2013-1267",
    "CVE-2013-1268",
    "CVE-2013-1269",
    "CVE-2013-1270",
    "CVE-2013-1271",
    "CVE-2013-1272",
    "CVE-2013-1273",
    "CVE-2013-1274",
    "CVE-2013-1275",
    "CVE-2013-1276",
    "CVE-2013-1277"
  );
  script_bugtraq_id(
    57786,
    57791,
    57792,
    57793,
    57794,
    57795,
    57796,
    57797,
    57798,
    57799,
    57800,
    57801,
    57802,
    57803,
    57804,
    57805,
    57806,
    57807,
    57808,
    57809,
    57810,
    57811,
    57812,
    57813,
    57814,
    57815,
    57816,
    57817,
    57818,
    57819
  );
  script_osvdb_id(
    90131,
    90132,
    90133,
    90134,
    90135,
    90136,
    90137,
    90138,
    90139,
    90140,
    90141,
    90142,
    90143,
    90144,
    90145,
    90146,
    90147,
    90148,
    90149,
    90150,
    90151,
    90152,
    90153,
    90154,
    90155,
    90156,
    90157,
    90158,
    90159,
    90160
  );
  script_xref(name:"MSFT", value:"MS13-016");

  script_name(english:"MS13-016: Vulnerabilities in Windows Kernel-Mode Driver Could Allow Elevation of Privilege (2778344)");
  script_summary(english:"Checks file version of Win32k.sys");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The Windows kernel on the remote host is affected by multiple race
condition vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Windows kernel on the remote host has several race condition
vulnerabilities.  A local attacker could exploit any of these
vulnerabilities to elevate privileges."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-016");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, 2008 R2, 8, and 2012."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS13-016';
kb = '2778344';

kbs = make_list(kb);
if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);
if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'0,1', win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Win32k.sys", version:"6.2.9200.20610", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Win32k.sys", version:"6.2.9200.16503", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 7 and Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Win32k.sys", version:"6.1.7601.22209", min_version:"6.1.7601.21000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Win32k.sys", version:"6.1.7601.18043", min_version:"6.1.7601.17000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Win32k.sys", version:"6.1.7600.21416", min_version:"6.1.7600.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Win32k.sys", version:"6.1.7600.17206", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Win32k.sys", version:"6.0.6002.23013", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Win32k.sys", version:"6.0.6002.18764", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2003 / XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Win32k.sys", version:"5.2.3790.5106",  dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Win32k.sys", version:"5.1.2600.6334", dir:"\system32", bulletin:bulletin, kb:kb)
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
