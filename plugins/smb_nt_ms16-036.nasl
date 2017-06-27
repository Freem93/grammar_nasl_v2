#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89835);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/04/18 13:50:38 $");

  script_cve_id(
    "CVE-2016-0960",
    "CVE-2016-0961",
    "CVE-2016-0962",
    "CVE-2016-0963",
    "CVE-2016-0986",
    "CVE-2016-0987",
    "CVE-2016-0988",
    "CVE-2016-0989",
    "CVE-2016-0990",
    "CVE-2016-0991",
    "CVE-2016-0992",
    "CVE-2016-0993",
    "CVE-2016-0994",
    "CVE-2016-0995",
    "CVE-2016-0996",
    "CVE-2016-0997",
    "CVE-2016-0998",
    "CVE-2016-0999",
    "CVE-2016-1000",
    "CVE-2016-1001",
    "CVE-2016-1002",
    "CVE-2016-1005",
    "CVE-2016-1010"
  );
  script_bugtraq_id(
    84308,
    84308,
    84310,
    84311,
    84312
  );
  script_osvdb_id(
    135679,
    135680,
    135681,
    135682,
    135683,
    135684,
    135685,
    135686,
    135687,
    135688,
    135689,
    135690,
    135691,
    135692,
    135693,
    135694,
    135695,
    135696,
    135697,
    135698,
    135699,
    135700,
    135701
  );
  script_xref(name:"MSFT", value:"MS16-036");

  script_name(english:"MS16-036: Security Update for Adobe Flash Player (3144756)");
  script_summary(english:"Checks the version of the ActiveX control.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing KB3144756. It is, therefore,
affected by multiple vulnerabilities :

  - Multiple integer overflow conditions exist that allow an
    attacker to execute arbitrary code. (CVE-2016-0963,
    CVE-2016-0993, CVE-2016-1010)

  - Multiple use-after-free errors exist that allow an
    attacker to execute arbitrary code. (CVE-2016-0987,
    CVE-2016-0988, CVE-2016-0990, CVE-2016-0991,
    CVE-2016-0994, CVE-2016-0995, CVE-2016-0996,
    CVE-2016-0997, CVE-2016-0998, CVE-2016-0999,
    CVE-2016-1000)

  - A heap overflow condition exists that allows an attacker
    to execute arbitrary code. (CVE-2016-1001)

  - Multiple memory corruption issues exist that allow an
    attacker to execute arbitrary code. (CVE-2016-0960,
    CVE-2016-0961, CVE-2016-0962, CVE-2016-0986,
    CVE-2016-0989, CVE-2016-0992, CVE-2016-1002,
    CVE-2016-1005)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-036");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-08.html");
  script_set_attribute(attribute:"solution", value:"
Microsoft has released a set of patches for Windows 2012, 8.1, RT 8.1,
2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/11");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:adobe:flash_player");
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
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_activex_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS16-036";
kbs = make_list("3144756");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

if (activex_init() != ACX_OK) audit(AUDIT_FN_FAIL, "activex_init()");

# Adobe Flash Player CLSID
clsid = '{D27CDB6E-AE6D-11cf-96B8-444553540000}';

file = activex_get_filename(clsid:clsid);
if (isnull(file))
{
  activex_end();
  audit(AUDIT_FN_FAIL, "activex_get_filename", "NULL");
}
if (!file)
{
  activex_end();
  audit(AUDIT_ACTIVEX_NOT_FOUND, clsid);
}

# Get its version.
version = activex_get_fileversion(clsid:clsid);
if (!version)
{
  activex_end();
  audit(AUDIT_VER_FAIL, file);
}

info = '';

iver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(iver); i++)
 iver[i] = int(iver[i]);
iver = join(iver, sep:".");

# all < 18.0.0.329 or 19 < 20.0.0.306
fix = FALSE;
if(iver =~ "^(19|20)\." && ver_compare(ver:iver, fix:"20.0.0.306", strict:FALSE) <= 0)
  fix = "21.0.0.182";
else if(ver_compare(ver:iver, fix:"18.0.0.329", strict:FALSE) <= 0)
  fix = "18.0.0.333";

if (
  (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0) &&
  fix
)
{
  info = '\n  Path              : ' + file +
         '\n  Installed version : ' + version +
         '\n  Fixed version     : ' + fix +
         '\n';
}

port = kb_smb_transport();

if (info != '')
{
  if (report_paranoia > 1)
  {
    report = info +
      '\n' +
      'Note, though, that Nessus did not check whether the kill bit was\n' +
      "set for the control's CLSID because of the Report Paranoia setting" + '\n' +
      'in effect when this scan was run.\n';
  }
  else
  {
    report = info +
      '\n' +
      'Moreover, its kill bit is not set so it is accessible via Internet\n' +
      'Explorer.\n';
  }
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_HOST_NOT, 'affected');
