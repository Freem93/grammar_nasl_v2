#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90443);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/04/18 13:50:38 $");

  script_cve_id(
    "CVE-2016-1006",
    "CVE-2016-1011",
    "CVE-2016-1012",
    "CVE-2016-1013",
    "CVE-2016-1014",
    "CVE-2016-1015",
    "CVE-2016-1016",
    "CVE-2016-1017",
    "CVE-2016-1018",
    "CVE-2016-1019",
    "CVE-2016-1020",
    "CVE-2016-1021",
    "CVE-2016-1022",
    "CVE-2016-1023",
    "CVE-2016-1024",
    "CVE-2016-1025",
    "CVE-2016-1026",
    "CVE-2016-1027",
    "CVE-2016-1028",
    "CVE-2016-1029",
    "CVE-2016-1030",
    "CVE-2016-1031",
    "CVE-2016-1032",
    "CVE-2016-1033"
  );
  script_bugtraq_id(
    85856,
    85926,
    85927,
    85928,
    85930,
    85931,
    85932,
    85932,
    85933
  );
  script_osvdb_id(
    135953,
    135957,
    135959,
    136683,
    136810,
    136811,
    136812,
    136813,
    136814,
    136817,
    136819,
    136820,
    136821,
    136822,
    136823,
    136824,
    136825,
    136826,
    136827,
    136828,
    136829,
    136830,
    136831,
    136832
  );
  script_xref(name:"MSFT", value:"MS16-050");
  script_xref(name:"ZDI", value:"ZDI-16-225");
  script_xref(name:"ZDI", value:"ZDI-16-226");
  script_xref(name:"ZDI", value:"ZDI-16-227");
  script_xref(name:"ZDI", value:"ZDI-16-228");

  script_name(english:"MS16-050: Security Update for Adobe Flash Player (3154132)");
  script_summary(english:"Checks the version of the ActiveX control.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing KB3154132. It is, therefore,
affected by multiple vulnerabilities :

  - An Address Space Layout Randomization (ASLR) bypass
    vulnerability exists that allows an attacker to predict
    memory offsets in the call stack. (CVE-2016-1006)

  - Multiple use-after-free errors exist that allow an
    attacker to execute arbitrary code. (CVE-2016-1011,
    CVE-2016-1013, CVE-2016-1016, CVE-2016-1017,
    CVE-2016-1031)

  - Multiple memory corruption issues exist that allow an
    attacker to execute arbitrary code. (CVE-2016-1012,
    CVE-2016-1020, CVE-2016-1021, CVE-2016-1022,
    CVE-2016-1023, CVE-2016-1024, CVE-2016-1025,
    CVE-2016-1026, CVE-2016-1027, CVE-2016-1028,
    CVE-2016-1029, CVE-2016-1032, CVE-2016-1033)

  - A directory search path vulnerability exists that allows
    an attacker to disclose sensitive resources.
    (CVE-2016-1014)

  - Multiple type confusion errors exist that allow an
    attacker to execute arbitrary code. (CVE-2016-1015,
    CVE-2016-1019)

  - An overflow condition exists that is triggered when
    handling JPEG-XR compressed image content. An attacker
    can exploit this to execute arbitrary code.
    (CVE-2016-1018)

  - An unspecified security bypass vulnerability exists.
    (CVE-2016-1030)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-050");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-10.html");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2012, 8.1, RT 8.1,
2012 R2, and 10. Alternatively, apply the workarounds as referenced in
the Microsoft advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/12");

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

bulletin = "MS16-050";
kbs = make_list("3154132");
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

fix = FALSE;
if(iver =~ "^(19|20|21)\." && ver_compare(ver:iver, fix:"21.0.0.197", strict:FALSE) <= 0)
  fix = "21.0.0.213";
else if(ver_compare(ver:iver, fix:"18.0.0.333", strict:FALSE) <= 0)
  fix = "18.0.0.343";

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
