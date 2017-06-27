#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81209);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/09 20:54:58 $");

  script_cve_id(
    "CVE-2015-0313",
    "CVE-2015-0314",
    "CVE-2015-0315",
    "CVE-2015-0316",
    "CVE-2015-0317",
    "CVE-2015-0318",
    "CVE-2015-0319",
    "CVE-2015-0320",
    "CVE-2015-0321",
    "CVE-2015-0322",
    "CVE-2015-0323",
    "CVE-2015-0324",
    "CVE-2015-0325",
    "CVE-2015-0326",
    "CVE-2015-0327",
    "CVE-2015-0328",
    "CVE-2015-0329",
    "CVE-2015-0330",
    "CVE-2015-0331"
  );
  script_bugtraq_id(72429, 72514, 72698);
  script_osvdb_id(
    117853,
    117967,
    117968,
    117969,
    117970,
    117971,
    117972,
    117973,
    117974,
    117975,
    117976,
    117977,
    117978,
    117979,
    117980,
    117981,
    117982,
    117983,
    118597
  );

  script_name(english:"MS KB3021953: Update for Vulnerabilities in Adobe Flash Player in Internet Explorer");
  script_summary(english:"Checks the version of the ActiveX control.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing KB3021953. It is, therefore, affected by
the following vulnerabilities :

  - Several use-after-free errors exist that allow arbitrary
    code execution. (CVE-2015-0313, CVE-2015-0315,
    CVE-2015-0320, CVE-2015-0322)

  - Several memory corruption errors exist that allow
    arbitrary code execution. (CVE-2015-0314,
    CVE-2015-0316, CVE-2015-0318, CVE-2015-0321,
    CVE-2015-0329, CVE-2015-0330)

  - Several type confusion errors exist that allow
    arbitrary code execution. (CVE-2015-0317, CVE-2015-0319)

  - Several heap-based buffer-overflow errors exist that
    allow arbitrary code execution. (CVE-2015-0323,
    CVE-2015-0327)

  - A buffer overflow error exists that allows arbitrary
    code execution. (CVE-2015-0324)

  - Several null pointer dereference errors exist that have
    unspecified impacts. (CVE-2015-0325, CVE-2015-0326,
    CVE-2015-0328)

  - A user-after-free error exists within the processing of
    invalid m3u8 playlists. A remote attacker, with a
    specially crafted m3u8 playlist file, can force a
    dangling pointer to be reused after it has been freed,
    allowing the execution of arbitrary code.
    (CVE-2015-0331)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/2755801");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/kb/3021953");
  script_set_attribute(attribute:"see_also", value:"http://helpx.adobe.com/security/products/flash-player/apsb15-04.html");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-047/");
  script_set_attribute(attribute:"solution", value:"Install Microsoft KB3021953.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player PCRE Regex Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
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

# < 16.0.0.305
if (
  (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0) &&
  (
    iver[0] < 16 ||
    (
      iver[0] == 16 &&
      (
        (iver[1] == 0 && iver[2] == 0 && iver[3] < 305)
      )
    )
  )
)
{
  info = '\n  Path              : ' + file +
         '\n  Installed version : ' + version +
         '\n  Fixed version     : 16.0.0.305' +
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
