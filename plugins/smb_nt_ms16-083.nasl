#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91672);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/04/18 13:50:38 $");

  script_cve_id(
    "CVE-2016-4122",
    "CVE-2016-4123",
    "CVE-2016-4124",
    "CVE-2016-4125",
    "CVE-2016-4127",
    "CVE-2016-4128",
    "CVE-2016-4129",
    "CVE-2016-4130",
    "CVE-2016-4131",
    "CVE-2016-4132",
    "CVE-2016-4133",
    "CVE-2016-4134",
    "CVE-2016-4135",
    "CVE-2016-4136",
    "CVE-2016-4137",
    "CVE-2016-4138",
    "CVE-2016-4139",
    "CVE-2016-4140",
    "CVE-2016-4141",
    "CVE-2016-4142",
    "CVE-2016-4143",
    "CVE-2016-4144",
    "CVE-2016-4145",
    "CVE-2016-4146",
    "CVE-2016-4147",
    "CVE-2016-4148",
    "CVE-2016-4149",
    "CVE-2016-4150",
    "CVE-2016-4151",
    "CVE-2016-4152",
    "CVE-2016-4153",
    "CVE-2016-4154",
    "CVE-2016-4155",
    "CVE-2016-4156",
    "CVE-2016-4166",
    "CVE-2016-4171"
  );
  script_bugtraq_id(
    91184,
    91249,
    91250,
    91251,
    91253,
    91255,
    91256
  );
  script_osvdb_id(
    139936,
    140015,
    140077,
    140078,
    140079,
    140080,
    140081,
    140082,
    140083,
    140084,
    140085,
    140086,
    140087,
    140088,
    140089,
    140090,
    140091,
    140092,
    140093,
    140094,
    140095,
    140096,
    140097,
    140098,
    140099,
    140100,
    140101,
    140102,
    140103,
    140104,
    140105,
    140106,
    140107,
    140108,
    140109,
    140110
  );
  script_xref(name:"MSFT", value:"MS16-083");
  script_xref(name:"CERT", value:"748992");

  script_name(english:"MS16-083: Security Update for Adobe Flash Player (3167685)");
  script_summary(english:"Checks the version of the ActiveX control.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing KB3167685. It is, therefore,
affected by multiple vulnerabilities :

  - Multiple memory corruption issues exist that allow an
    unauthenticated, remote attacker to cause a denial of
    service condition or the execution of arbitrary code.
    (CVE-2016-4122, CVE-2016-4123, CVE-2016-4124,
    CVE-2016-4125, CVE-2016-4127, CVE-2016-4128,
    CVE-2016-4129, CVE-2016-4130, CVE-2016-4131,
    CVE-2016-4132, CVE-2016-4133, CVE-2016-4134,
    CVE-2016-4137, CVE-2016-4141, CVE-2016-4150,
    CVE-2016-4151, CVE-2016-4152, CVE-2016-4153,
    CVE-2016-4154, CVE-2016-4155, CVE-2016-4156,
    CVE-2016-4166, CVE-2016-4171)

  - Multiple heap buffer overflow conditions exist due to
    improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit these to
    execute arbitrary code. (CVE-2016-4135, CVE-2016-4136,
    CVE-2016-4138).

  - An unspecified vulnerability exists that allows an
    unauthenticated, remote attacker to bypass the
    same-origin policy, resulting in the disclosure of
    potentially sensitive information. (CVE-2016-4139)

  - An unspecified flaw exists when loading certain dynamic
    link libraries due to using a search path that includes
    directories which may not be trusted or under the user's
    control. An unauthenticated, remote attacker can exploit
    this, by inserting a specially crafted library in the
    path, to execute arbitrary code in the context of the
    user. (CVE-2016-4140)

  - Multiple use-after-free errors exist that allow an
    unauthenticated, remote attacker to deference already
    freed memory, resulting in the execution of arbitrary
    code. (CVE-2016-4142, CVE-2016-4143, CVE-2016-4145,
    CVE-2016-4146, CVE-2016-4147, CVE-2016-4148)

  - Multiple type confusion errors exist that allow an
    unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2016-4144, CVE-2016-4149)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-083");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-18.html");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/17");

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

bulletin = "MS16-083";
kbs = make_list("3167685");
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
if(iver =~ "^(19|2[01])\." && ver_compare(ver:iver, fix:"21.0.0.242", strict:FALSE) <= 0)
  fix = "22.0.0.192";
else if(ver_compare(ver:iver, fix:"18.0.0.352", strict:FALSE) <= 0)
  fix = "18.0.0.360";

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
