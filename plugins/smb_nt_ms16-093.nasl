#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92024);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/04/18 13:50:38 $");

  script_cve_id(
    "CVE-2016-4172",
    "CVE-2016-4173",
    "CVE-2016-4174",
    "CVE-2016-4175",
    "CVE-2016-4176",
    "CVE-2016-4177",
    "CVE-2016-4178",
    "CVE-2016-4179",
    "CVE-2016-4180",
    "CVE-2016-4181",
    "CVE-2016-4182",
    "CVE-2016-4183",
    "CVE-2016-4184",
    "CVE-2016-4185",
    "CVE-2016-4186",
    "CVE-2016-4187",
    "CVE-2016-4188",
    "CVE-2016-4189",
    "CVE-2016-4190",
    "CVE-2016-4217",
    "CVE-2016-4218",
    "CVE-2016-4219",
    "CVE-2016-4220",
    "CVE-2016-4221",
    "CVE-2016-4222",
    "CVE-2016-4223",
    "CVE-2016-4224",
    "CVE-2016-4225",
    "CVE-2016-4226",
    "CVE-2016-4227",
    "CVE-2016-4228",
    "CVE-2016-4229",
    "CVE-2016-4230",
    "CVE-2016-4231",
    "CVE-2016-4232",
    "CVE-2016-4233",
    "CVE-2016-4234",
    "CVE-2016-4235",
    "CVE-2016-4236",
    "CVE-2016-4237",
    "CVE-2016-4238",
    "CVE-2016-4239",
    "CVE-2016-4240",
    "CVE-2016-4241",
    "CVE-2016-4242",
    "CVE-2016-4243",
    "CVE-2016-4244",
    "CVE-2016-4245",
    "CVE-2016-4246",
    "CVE-2016-4247",
    "CVE-2016-4248",
    "CVE-2016-4249",
    "CVE-2016-7020"
  );
  script_bugtraq_id(
    91718,
    91719,
    91720,
    91721,
    91722,
    91723,
    91724,
    91725
  );
  script_osvdb_id(
    141309,
    141310,
    141311,
    141312,
    141313,
    141314,
    141315,
    141316,
    141317,
    141318,
    141319,
    141320,
    141321,
    141322,
    141323,
    141324,
    141325,
    141326,
    141327,
    141328,
    141329,
    141330,
    141331,
    141332,
    141333,
    141334,
    141335,
    141336,
    141337,
    141338,
    141339,
    141340,
    141341,
    141342,
    141343,
    141344,
    141345,
    141346,
    141347,
    141348,
    141349,
    141350,
    141351,
    141352,
    141353,
    141354,
    141355,
    141356,
    141359,
    141360,
    141380,
    141381,
    145170
  );
  script_xref(name:"MSFT", value:"MS16-093");

  script_name(english:"MS16-093: Security Update for Adobe Flash Player (3174060)");
  script_summary(english:"Checks the version of the ActiveX control.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing KB3174060. It is, therefore,
affected by multiple vulnerabilities :

  - Multiple memory corruption issues exist that allow a
    remote attacker to execute arbitrary code.
    (CVE-2016-4172, CVE-2016-4175, CVE-2016-4179,
    CVE-2016-4180, CVE-2016-4181, CVE-2016-4182,
    CVE-2016-4183, CVE-2016-4184, CVE-2016-4185,
    CVE-2016-4186, CVE-2016-4187, CVE-2016-4188,
    CVE-2016-4189, CVE-2016-4190, CVE-2016-4217,
    CVE-2016-4218, CVE-2016-4219, CVE-2016-4220,
    CVE-2016-4221, CVE-2016-4233, CVE-2016-4234,
    CVE-2016-4235, CVE-2016-4236, CVE-2016-4237,
    CVE-2016-4238, CVE-2016-4239, CVE-2016-4240,
    CVE-2016-4241, CVE-2016-4242, CVE-2016-4243,
    CVE-2016-4244, CVE-2016-4245, CVE-2016-4246)

  - Multiple use-after-free errors exist that allow a remote
    attacker to execute arbitrary code. (CVE-2016-4173,
    CVE-2016-4174, CVE-2016-4222, CVE-2016-4226,
    CVE-2016-4227, CVE-2016-4228, CVE-2016-4229,
    CVE-2016-4230, CVE-2016-4231, CVE-2016-4248,
    CVE-2016-7020)

  - Multiple stack corruption issues exist that allow a
    remote attacker to execute arbitrary code.
    (CVE-2016-4176, CVE-2016-4177)

  - A security bypass vulnerability exists that allows a
    remote attacker to disclose sensitive information.
    (CVE-2016-4178)

  - Multiple type confusion errors exist that allow a remote
    attacker to execute arbitrary code. (CVE-2016-4223,
    CVE-2016-4224, CVE-2016-4225)

  - An unspecified memory leak issue exists that allows an
    attacker to have an unspecified impact. (CVE-2016-4232)

  - A race condition exists that allows a remote attacker to
    disclose sensitive information. (CVE-2016-4247)

  - A heap buffer overflow condition exists that allows a
    remote attacker to execute arbitrary code.
    (CVE-2016-4249)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-093");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-25.html");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2012, 8.1, RT 8.1,
2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/12");

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

bulletin = "MS16-093";
kbs = make_list("3174060");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "Windows 8.1" >!< productname) audit(AUDIT_OS_SP_NOT_VULN);

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

# all <= 18.0.0.352 or 19 <= 21.0.0.242
fix = FALSE;
if(iver =~ "^(19|2[01])\." && ver_compare(ver:iver, fix:"22.0.0.192", strict:FALSE) <= 0)
  fix = "22.0.0.209";
else if(ver_compare(ver:iver, fix:"18.0.0.360", strict:FALSE) <= 0)
  fix = "18.0.0.366";

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
