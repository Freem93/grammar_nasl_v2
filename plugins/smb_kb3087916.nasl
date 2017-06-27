#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85329);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/22 14:57:57 $");

  script_cve_id(
    "CVE-2015-3107",
    "CVE-2015-5125",
    "CVE-2015-5127",
    "CVE-2015-5128",
    "CVE-2015-5129",
    "CVE-2015-5130",
    "CVE-2015-5131",
    "CVE-2015-5132",
    "CVE-2015-5133",
    "CVE-2015-5134",
    "CVE-2015-5539",
    "CVE-2015-5540",
    "CVE-2015-5541",
    "CVE-2015-5544",
    "CVE-2015-5545",
    "CVE-2015-5546",
    "CVE-2015-5547",
    "CVE-2015-5548",
    "CVE-2015-5549",
    "CVE-2015-5550",
    "CVE-2015-5551",
    "CVE-2015-5552",
    "CVE-2015-5553",
    "CVE-2015-5554",
    "CVE-2015-5555",
    "CVE-2015-5556",
    "CVE-2015-5557",
    "CVE-2015-5558",
    "CVE-2015-5559",
    "CVE-2015-5560",
    "CVE-2015-5561",
    "CVE-2015-5562",
    "CVE-2015-5563",
    "CVE-2015-5564",
    "CVE-2015-5565",
    "CVE-2015-5566"
  );
  script_bugtraq_id(
    75087,
    76282,
    76283,
    76287,
    76288,
    76289,
    76291
  );
  script_osvdb_id(
    125910,
    125911,
    125912,
    125913,
    125914,
    125915,
    125916,
    125917,
    125918,
    125919,
    125920,
    125921,
    125922,
    125923,
    125924,
    125925,
    125926,
    125927,
    125928,
    125929,
    125930,
    125931,
    125932,
    125933,
    125934,
    125935,
    125936,
    125937,
    125938,
    125939,
    125940,
    125941,
    126086,
    126087,
    126597
  );

  script_name(english:"MS KB3087916: Update for Vulnerabilities in Adobe Flash Player in Internet Explorer");
  script_summary(english:"Checks the version of the ActiveX control.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin installed that is
affected by multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing KB3087916. It is, therefore,
affected by multiple remote code execution vulnerabilities :

   - Multiple type confusion errors exist that allow an
    attacker to execute arbitrary code. (CVE-2015-5128,
    CVE-2015-5554, CVE-2015-5555, CVE-2015-5558,
    CVE-2015-5562)

  - An unspecified vulnerability exists related to vector
    length corruptions. (CVE-2015-5125)

  - Multiple user-after-free errors exist that allow an
    attacker to execute arbitrary code. (CVE-2015-5550,
    CVE-2015-5551, CVE-2015-3107, CVE-2015-5556,
    CVE-2015-5130, CVE-2015-5134, CVE-2015-5539,
    CVE-2015-5540, CVE-2015-5557, CVE-2015-5559,
    CVE-2015-5127, CVE-2015-5563, CVE-2015-5561,
    CVE-2015-5564, CVE-2015-5565, CVE-2015-5566)
  
  - Multiple heap buffer overflow conditions exist that
    allow an attacker to execute arbitrary code.
    (CVE-2015-5129, CVE-2015-5541)

  - Multiple buffer overflow conditions exist that allow an
    attacker to execute arbitrary code. (CVE-2015-5131,
    CVE-2015-5132, CVE-2015-5133)
  
  - Multiple memory corruption issues exist that allow an
    attacker to execute arbitrary code. (CVE-2015-5544,
    CVE-2015-5545, CVE-2015-5546, CVE-2015-5547,
    CVE-2015-5548, CVE-2015-5549, CVE-2015-5552,
    CVE-2015-5553)

  - An integer overflow condition exists that allows an
    attacker to execute arbitrary code. (CVE-2015-5560)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-19.html");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/kb/3087916");
  script_set_attribute(attribute:"solution", value:"Install Microsoft KB3087916.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/08/11");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/11");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_activex_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
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

# <= 18.0.0.209.
if (
  (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0) &&
  (
    iver[0] < 18 ||
    (
      iver[0] == 18 &&
      (
        (iver[1] == 0 && iver[2] == 0 && iver[3] <= 228)
      )
    )
  )
)
{
  info = '\n  Path              : ' + file +
         '\n  Installed version : ' + version +
         '\n  Fixed version     : 18.0.0.232' +
         '\n';
}

port = kb_smb_transport();

if (info != '')
{
  if (report_verbosity > 0)
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
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_HOST_NOT, 'affected');
